import copy
import hashlib
from attack_rules import exploits_for, escalation_for
import re
import networkx as nx

class MultiAgentCyberEngine:
    def __init__(self, semantic_net: nx.DiGraph, config: dict, scenario="killchain", seed=42):
        self.scenario = scenario
        self.seed = seed
        self.had_compromise = False
        self.outcome = "Running"
        self.compromised_ever = set()
        self.encrypted_ever = set()
        self.unavailable_host_turns = 0
        self.first_detection_turn = None
        self.recovered_hosts = 0
        self.base_graph = semantic_net
        self.config = config
        self.agents = ["red_agent", "blue_agent"]
        
        self.exploits = config.get("exploits", {})
        self.priv_esc = config.get("privilege_escalation", {})
        self.sensitive_hosts = config.get("sensitive_hosts", {})

        self.graph = copy.deepcopy(self.base_graph)
        self.turn = 0
        self.max_turns = 21
        self.score = 0
        self.attacker_access = {}
        self.event_log = []

    def reset(self):
        """Resets the environment and returns observations for all agents."""
        self.graph = copy.deepcopy(self.base_graph)
        self.turn = 0
        self.score = 0
        self.attacker_access = {}
        self.event_log = []

        for node in self.graph.nodes():
            self.graph.nodes[node]["status"] = "safe"
            self.graph.nodes[node]["access"] = "none"
            self.graph.nodes[node]["encrypted"] = False

        self.had_compromise = False
        self.outcome = "Running"
        self.compromised_ever = set()
        self.encrypted_ever = set()
        self.unavailable_host_turns = 0
        self.first_detection_turn = None
        self.recovered_hosts = 0
        self._log(f"Simulation initialized. Scenario: {self.scenario}; seed: {self.seed}.")

        observations = {
            "red_agent": self._get_red_observation(),
            "blue_agent": self._get_blue_observation()
        }
        return observations, {}

    def step(self, actions: dict):
        """
        Advances turn, resolves agent actions, calculates rewards, and logs events.
        actions format: {"red_agent": ("pivot", node, svc), "blue_agent": ("isolate", node)}
        """
        self.turn += 1
        rewards = {"red_agent": 0, "blue_agent": 0}
        
        # 1. Resolve Red Action & Log
        red_action = actions.get("red_agent")
        wave = red_action if isinstance(red_action, list) else [red_action]
        for action in wave:
            red_msg = self._resolve_attack(action)
            if red_msg:
                self._log(f"[RED] {red_msg}")
        
        # 2. Resolve Blue Action & Log
        blue_action = actions.get("blue_agent")
        blue_msg = self._resolve_defense(blue_action)
        if blue_msg:
            self._log(f"[BLUE] {blue_msg}")
        
        # 3. Calculate Zero-Sum Rewards
        current_score_delta = self._calculate_rewards()
        rewards["red_agent"] = current_score_delta
        rewards["blue_agent"] = -current_score_delta

        # 4. Check Termination & Truncation
        terminated, term_reason = self._check_termination()
        if terminated and term_reason:
            self._log(f"[GAME OVER] {term_reason}")

        truncated = self.turn >= self.max_turns
        if truncated and not terminated:
            self.outcome = "Time limit reached"
            self._log("[GAME OVER] Max turns reached.")
        
        terminations = {"red_agent": terminated, "blue_agent": terminated, "__all__": terminated}
        truncations = {"red_agent": truncated, "blue_agent": truncated, "__all__": truncated}
        
        observations = {
            "red_agent": self._get_red_observation(),
            "blue_agent": self._get_blue_observation()
        }
        
        return observations, rewards, terminations, truncations, {"turn": self.turn, "score": self.score}

    def damage(self):
        """Current control, encryption damage, and isolation downtime."""
        control = sum(max(5, self.graph.nodes[n].get("value", 0)) *
                      (2 if level == "root" else 1)
                      for n, level in self.attacker_access.items()
                      if self.graph.nodes[n]["status"] != "isolated")
        encrypted = sum(d.get("encrypted", False) for _, d in self.graph.nodes(data=True))
        unavailable = sum(d.get("subnet") != 0 and d["status"] in ("encrypted", "isolated")
                          for _, d in self.graph.nodes(data=True))
        return control + encrypted * 100 + unavailable * 10

    def _calculate_rewards(self):
        reward_delta = self.damage()
        self.score += reward_delta
        self.unavailable_host_turns += sum(
            d.get("subnet") != 0 and d["status"] in ("encrypted", "isolated")
            for _, d in self.graph.nodes(data=True))
        return reward_delta

    def _check_termination(self):
        active = [n for n in self.attacker_access if self.graph.nodes[n]["status"] != "isolated"]
        encrypted = [n for n, d in self.graph.nodes(data=True) if d.get("encrypted", False)]
        if self.scenario == "killchain":
            for node in active:
                if self.attacker_access[node] == "root" and self.graph.nodes[node].get("value", 0) >= 100:
                    self.outcome = "Attacker victory"
                    return True, f"Attacker fully breached sensitive host {node} (Red Victory)."
        else:
            reachable = set(active)
            for node in active:
                reachable.update(nx.descendants(self.graph, node))
            encryptable = [n for n in reachable if self.graph.nodes[n]["status"] != "isolated"
                           and (self.attacker_access.get(n) == "root" or
                                escalation_for(self.config, self.graph, n))]
            if encryptable and all(self.graph.nodes[n]["status"] == "encrypted" for n in encryptable):
                self.outcome = "Attacker victory"
                return True, "Ransomware encrypted all remaining reachable encryptable hosts (Red Victory)."
        if self.had_compromise and not active and not encrypted:
            self.outcome = "Defender victory"
            return True, "Defender contained or removed all active compromises (Blue Victory)."
        return False, ""

    def _get_red_observation(self):
        return {
            "attacker_access": dict(self.attacker_access),
            "graph_summary": list(self.graph.nodes(data=True))
        }

    def _get_blue_observation(self):
        return {
            "graph": self.graph.copy(),
            "active_threat_count": len([
                n for n in self.attacker_access 
                if self.graph.nodes[n]["status"] != "isolated"
            ]),
            "attacker_access": dict(self.attacker_access),
            "event_log": list(self.event_log)
        }

    def _resolve_attack(self, action):
        if not action or action[0] == "sleep":
            return "Attacker scanning network (No action)."
            
        action_type = action[0]
        target = action[1]
        detail = action[2] if len(action) > 2 else None
        
        if target not in self.graph:
            return f"Attack target {target} does not exist."
            
        if self.graph.nodes[target]["status"] == "isolated":
            return f"Attack blocked. Target {target} is physically isolated."

        host = self.graph.nodes[target]
        if action_type == "ransomware":
            if self.attacker_access.get(target) != "root":
                return f"Encryption blocked on {target}: root access required."
            if host["status"] == "encrypted":
                return f"Host {target} already encrypted."
            host["status"] = "encrypted"
            host["encrypted"] = True
            self.encrypted_ever.add(target)
            return f"Ransomware payload detonated. {target} is ENCRYPTED."

        if action_type in ("exploit", "pivot"):
            if target in self.attacker_access:
                return f"Host {target} already compromised."
            source = action[3] if len(action) > 3 else "(0, 0)"
            if action_type == "pivot" and (source not in self.attacker_access or
                                            self.graph.nodes[source]["status"] == "isolated"):
                return f"Pivot blocked: no active foothold at {source}."
            if not self.graph.has_edge(source, target):
                return f"Attack blocked: no permitted connection from {source} to {target}."
            allowed = self.graph.edges[source, target].get("allowed_services", [])
            eligible = dict(exploits_for(self.config, self.graph, target, allowed))
            if detail not in eligible:
                return f"Attack blocked on {target}: exploit {detail} is incompatible with service, OS, or firewall."
            rule = eligible[detail]
            if self._succeeds(action, rule["prob"]):
                access = rule.get("access", "user")
                self.attacker_access[target] = access
                host.update(status="compromised", access=access)
                self.had_compromise = True
                self.compromised_ever.add(target)
                return f"Breach succeeded on {target} via {detail}."
            return f"Exploit attempt on {target} via {detail} failed."

        if action_type == "escalate":
            if self.attacker_access.get(target) != "user":
                return f"Privilege escalation blocked on {target}: user foothold required."
            name = detail or escalation_for(self.config, self.graph, target)
            rule = self.priv_esc.get(name, {})
            if (not rule or rule.get("process") not in host.get("processes", [])
                    or rule.get("os") not in (None, "None", host.get("os"))):
                return f"Privilege escalation blocked on {target}: no compatible process."
            if self._succeeds(action, rule.get("prob", 0)):
                self.attacker_access[target] = "root"
                host["access"] = "root"
                return f"Privilege escalated to root on {target}."
            return f"Privilege escalation attempt on {target} failed."
        return "Action unrecognized or blocked."

    def _succeeds(self, action, probability):
        # Defense lookahead and wave ordering cannot consume real attack draws.
        key = repr((self.seed, self.turn, tuple(action))).encode()
        draw = int.from_bytes(hashlib.sha256(key).digest()[:8], "big") / 2**64
        return draw < probability

    def _resolve_defense(self, blue_action):
        if not blue_action:
            return "Defender standing by."

        action_type = blue_action[0]
        target = blue_action[1] if len(blue_action) > 1 else None

        if action_type == "isolate" and target in self.graph:
            self._record_response()
            in_edges = list(self.graph.in_edges(target))
            out_edges = list(self.graph.out_edges(target))
            self.graph.remove_edges_from(in_edges + out_edges)
            
            self.graph.nodes[target]["status"] = "isolated"
            return f"Isolated node {target}. Ingress and egress severed."

        elif (action_type == "remediate" and target in self.attacker_access
              and self.graph.nodes[target]["status"] == "compromised"):
            self._record_response()
            del self.attacker_access[target]
            self.graph.nodes[target]["status"] = "safe"
            self.graph.nodes[target]["access"] = "none"
            return f"Remediated node {target}. Malware cleared and credentials revoked."

        elif action_type == "restore_backup" and target in self.graph:
            if self.graph.nodes[target].get("encrypted", False):
                self._record_response()
                self.graph.nodes[target]["encrypted"] = False
                if self.graph.nodes[target]["status"] != "isolated":
                    self.graph.nodes[target]["status"] = "safe"
                self.graph.nodes[target]["access"] = "none"
                self.recovered_hosts += 1
                # Remove attacker access since the backup is clean
                if target in self.attacker_access:
                    del self.attacker_access[target]
                return f"Restored {target} from immutable backups. Node safe."

            
        elif action_type == "sleep":
            return "Defender monitoring alerts (no intervention)."

        return None

    def _record_response(self):
        if self.first_detection_turn is None:
            self.first_detection_turn = self.turn

    def _log(self, text: str):
        entry = f"[Turn {self.turn:02d}] {text}"
        self.event_log.append(entry)

    def export_xyflow_json(self):
        """Converts graph and logs into the exact format required by @xyflow/react."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            # Parse (subnet, host_idx) from "(1, 2)" format if host_idx is missing
            subnet = data.get("subnet", 0)
            host_idx = data.get("host_idx")
            if host_idx is None:
                match = re.findall(r"\d+", str(node_id))
                host_idx = int(match[1]) if len(match) >= 2 else 0

            nodes.append({
                "id": str(node_id),
                "data": {
                    "label": str(node_id),
                    "status": data.get("status", "safe"),
                    "access": data.get("access", "none"),
                    "subnet": subnet,
                    "os": data.get("os", ""),
                    "services": data.get("services", []),
                    "value": data.get("value", 0)
                },
                "position": {
                    "x": int(subnet) * 240, 
                    "y": int(host_idx) * 110
                }
            })

        edges = []
        for idx, (u, v, data) in enumerate(self.graph.edges(data=True)):
            edges.append({
                "id": f"e-{u}-{v}-{idx}",
                "source": str(u),
                "target": str(v),
                "animated": u in self.attacker_access and self.graph.nodes[u]["status"] != "isolated",
                "data": {
                    "allowed_services": data.get("allowed_services", [])
                }
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "event_log": self.event_log[-12:],
            "score": self.score,
            "turn": self.turn,
            "scenario": self.scenario,
            "seed": self.seed,
            "outcome": self.outcome,
            "metrics": {
                "compromised_hosts": len(self.compromised_ever),
                "encrypted_hosts": sum(d.get("encrypted", False) for _, d in self.graph.nodes(data=True)),
                "ever_encrypted_hosts": len(self.encrypted_ever),
                "unavailable_host_turns": self.unavailable_host_turns,
                "first_detection_turn": self.first_detection_turn,
                "recovered_hosts": self.recovered_hosts,
            }
        }
