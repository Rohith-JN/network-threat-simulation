import copy
import unittest
from unittest.mock import patch, AsyncMock

from build_semantic_net import parse_nasim_yaml
from engine import MultiAgentCyberEngine
from red_agent import HybridRedAgent, RansomwareAgent
from blue_agent import HybridBlueAgent


def run_scenario(scenario, defended, seed=42, filename="tiny.yaml"):
    graph, config = parse_nasim_yaml(filename)
    env = MultiAgentCyberEngine(graph, config, scenario, seed)
    red = (RansomwareAgent if scenario == "ransomware" else HybridRedAgent)(config, seed)
    blue = HybridBlueAgent()
    observations, _ = env.reset()
    while True:
        defense = blue.get_action(env, observations["blue_agent"], red) if defended else ("sleep", None)
        attack = red.get_optimal_attack_step(env.graph, env.attacker_access)
        observations, _, term, trunc, _ = env.step({"red_agent": attack, "blue_agent": defense})
        if term["__all__"] or trunc["__all__"]:
            return env


class SimulationTests(unittest.TestCase):
    def setUp(self):
        self.graph, self.config = parse_nasim_yaml("tiny.yaml")
        self.env = MultiAgentCyberEngine(self.graph, self.config)
        self.env.reset()

    def breach(self, target="(1, 0)", exploit="e_http", source=None):
        action = ("pivot", target, exploit, source) if source else ("exploit", target, exploit)
        with patch.object(self.env, "_succeeds", return_value=True):
            self.env._resolve_attack(action)

    def test_configured_probability_and_access_are_used(self):
        self.config["exploits"]["e_http"]["prob"] = 0.37
        self.config["exploits"]["e_http"]["access"] = "root"
        with patch.object(self.env, "_succeeds", return_value=True) as draw:
            self.env._resolve_attack(("exploit", "(1, 0)", "e_http"))
        draw.assert_called_once_with(("exploit", "(1, 0)", "e_http"), 0.37)
        self.assertEqual(self.env.attacker_access["(1, 0)"], "root")

    def test_incompatible_exploit_and_firewall_are_blocked(self):
        self.breach(exploit="e_ssh")
        self.assertFalse(self.env.attacker_access)
        self.breach()
        self.breach("(3, 1)", "e_http", "(1, 0)")
        self.assertNotIn("(3, 1)", self.env.attacker_access)

    def test_os_and_pivot_foothold_are_required(self):
        self.env.graph.nodes["(1, 0)"]["services"] = ["ftp"]
        self.env.graph.edges["(0, 0)", "(1, 0)"]["allowed_services"] = ["ftp"]
        self.breach(exploit="e_ftp")
        self.assertFalse(self.env.attacker_access)
        self.breach("(2, 0)", "e_ssh", "(1, 0)")
        self.assertFalse(self.env.attacker_access)

    def test_escalation_requires_compatible_process(self):
        self.breach()
        self.env._resolve_attack(("escalate", "(1, 0)", "pe_tomcat"))
        self.assertEqual(self.env.attacker_access["(1, 0)"], "user")
        self.breach("(2, 0)", "e_ssh", "(1, 0)")
        with patch.object(self.env, "_succeeds", return_value=True) as draw:
            self.env._resolve_attack(("escalate", "(2, 0)", "pe_tomcat"))
        self.assertEqual(draw.call_args.args[1], 1.0)
        self.assertEqual(self.env.attacker_access["(2, 0)"], "root")

    def test_ransomware_requires_root_and_does_not_end_at_root(self):
        self.env.scenario = "ransomware"
        self.breach()
        self.env._resolve_attack(("ransomware", "(1, 0)", None))
        self.assertFalse(self.env.encrypted_ever)
        self.breach("(2, 0)", "e_ssh", "(1, 0)")
        self.env._resolve_attack(("escalate", "(2, 0)", "pe_tomcat"))
        self.assertFalse(self.env._check_termination()[0])

    def test_wave_is_one_turn_with_one_defense(self):
        self.breach()
        self.breach("(2, 0)", "e_ssh", "(1, 0)")
        wave = RansomwareAgent(self.config).get_optimal_attack_step(self.env.graph, self.env.attacker_access)
        self.assertGreater(len(wave), 1)
        _, rewards, _, _, _ = self.env.step({"red_agent": wave, "blue_agent": ("sleep", None)})
        self.assertEqual(self.env.turn, 1)
        self.assertEqual(rewards["red_agent"], self.env.score)
        self.assertEqual(sum("[BLUE]" in log for log in self.env.event_log), 1)

    def test_restore_clears_access_but_preserves_damage_history(self):
        self.breach()
        self.env.attacker_access["(1, 0)"] = "root"
        self.env._resolve_attack(("ransomware", "(1, 0)", None))
        self.env._calculate_rewards()
        score = self.env.score
        self.env._resolve_defense(("restore_backup", "(1, 0)"))
        self.assertNotIn("(1, 0)", self.env.attacker_access)
        self.assertEqual(self.env.graph.nodes["(1, 0)"]["access"], "none")
        self.assertEqual(self.env.score, score)
        self.assertEqual(len(self.env.encrypted_ever), 1)
        self.assertTrue(self.env._check_termination()[0])

    def test_isolation_does_not_erase_encryption(self):
        self.breach()
        self.env.attacker_access["(1, 0)"] = "root"
        self.env._resolve_attack(("ransomware", "(1, 0)", None))
        self.env._resolve_defense(("isolate", "(1, 0)"))
        self.assertEqual(self.env.export_xyflow_json()["metrics"]["encrypted_hosts"], 1)
        self.assertFalse(self.env._check_termination()[0])

    def test_lookahead_does_not_mutate_live_attacker_or_environment(self):
        self.breach()
        self.env._log("[RED] Breach succeeded on (1, 0) via e_http.")
        red = RansomwareAgent(self.config)
        before = copy.deepcopy(self.env.export_xyflow_json())
        rng = red.rng.getstate()
        HybridBlueAgent().get_action(self.env, self.env._get_blue_observation(), red)
        self.assertEqual(before, self.env.export_xyflow_json())
        self.assertEqual(rng, red.rng.getstate())

    def test_old_alerts_are_not_reprocessed(self):
        blue = HybridBlueAgent()
        logs = ["Exploit attempt on (1, 0) via e_http failed."]
        blue._bayesian_update(logs)
        blue._bayesian_update(logs)
        self.assertEqual(blue.belief_state["(1, 0)"], 0.4)

    def test_reproducibility_and_defense_effect(self):
        for scenario in ("killchain", "ransomware"):
            with self.subTest(scenario=scenario):
                unhindered = run_scenario(scenario, False)
                repeat = run_scenario(scenario, False)
                defended = run_scenario(scenario, True)
                self.assertEqual(unhindered.export_xyflow_json(), repeat.export_xyflow_json())
                self.assertLess(defended.score, unhindered.score)
                self.assertGreater(defended.first_detection_turn, 0)
                if scenario == "ransomware":
                    self.assertGreater(len(unhindered.encrypted_ever), len(defended.encrypted_ever))

    def test_websocket_init_and_all_supported_commands(self):
        from fastapi.testclient import TestClient
        from server import app
        with TestClient(app) as client, patch("server.asyncio.sleep", new_callable=AsyncMock):
            with client.websocket_connect("/ws/simulation") as ws:
                ws.send_text("init")
                self.assertEqual(len(ws.receive_json()["nodes"]), 9)
                for scenario in ("killchain", "ransomware"):
                    for mode in ("defended", "unhindered"):
                        ws.send_text(f"{scenario}_{mode}")
                        initial = ws.receive_json()
                        self.assertEqual(initial["turn"], 0)
                        while True:
                            result = ws.receive_json()
                            self.assertEqual(result["scenario"], scenario)
                            self.assertLessEqual(result["turn"], 21)
                            if result["outcome"] != "Running":
                                break
                        self.assertEqual(result["seed"], 42)


if __name__ == "__main__":
    unittest.main()
