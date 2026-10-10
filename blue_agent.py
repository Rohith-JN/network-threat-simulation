import copy
import re


class HybridBlueAgent:
    def __init__(self):
        self.belief_state = {}
        self.processed_logs = 0

    def _bayesian_update(self, event_log):
        # Process each alert once; old failures must not become fresh evidence.
        for log in event_log[self.processed_logs:]:
            match = re.search(r"\((\d+),\s*(\d+)\)", log)
            if not match:
                continue
            node = f"({match.group(1)}, {match.group(2)})"
            if "Breach succeeded on" in log or "Privilege escalated" in log:
                self.belief_state[node] = 0.95
            elif "Exploit attempt on" in log:
                self.belief_state[node] = min(1, self.belief_state.get(node, 0) + 0.4)
            elif "Remediated node" in log or "Restored" in log or "Isolated node" in log:
                self.belief_state[node] = 0
        self.processed_logs = len(event_log)

    def get_action(self, current_env, obs, red_ai):
        self._bayesian_update(obs.get("event_log", []))
        sim_env = copy.deepcopy(current_env)
        # Infer ownership from alerts and observed state, without copying secret access.
        sim_env.attacker_access = {}
        valid_actions = [("sleep", None)]
        for node, data in sim_env.graph.nodes(data=True):
            if data.get("encrypted", False):
                valid_actions.append(("restore_backup", node))
                if data["status"] != "isolated":
                    sim_env.attacker_access[node] = "root"
                    valid_actions.append(("isolate", node))
            elif self.belief_state.get(node, 0) > 0.8 and data["status"] == "compromised":
                sim_env.attacker_access[node] = data.get("access", "user")
                valid_actions.extend([("remediate", node), ("isolate", node)])

        best_action = valid_actions[0]
        best_cost = float("inf")
        for action in valid_actions:
            hypothetical = copy.deepcopy(sim_env)
            # Real turns resolve the attacker wave before the defender. Score that
            # same order, then predict another wave to include containment value.
            predicted_red = copy.deepcopy(red_ai)
            wave = predicted_red.get_optimal_attack_step(hypothetical.graph, hypothetical.attacker_access)
            wave = wave if isinstance(wave, list) else [wave]
            hypothetical.turn += 1
            for red_action in wave:
                hypothetical._resolve_attack(red_action)
            hypothetical._resolve_defense(action)
            cost = hypothetical.damage()
            next_wave = predicted_red.get_optimal_attack_step(hypothetical.graph, hypothetical.attacker_access)
            next_wave = next_wave if isinstance(next_wave, list) else [next_wave]
            hypothetical.turn += 1
            for red_action in next_wave:
                hypothetical._resolve_attack(red_action)
            cost += hypothetical.damage()
            if cost < best_cost:
                best_cost = cost
                best_action = action
        return best_action
