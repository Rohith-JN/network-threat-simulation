import copy
import random
import re
import networkx as nx

class MultiAgentCyberEngine:
    def __init__(self, semantic_net: nx.DiGraph, config: dict):
        self.base_graph = semantic_net
        self.config = config
        self.agents = ["red_agent", "blue_agent"]
        
        self.exploits = config.get("exploits", {})
        self.priv_esc = config.get("privilege_escalation", {})
        self.sensitive_hosts = config.get("sensitive_hosts", {})

        self.graph = copy.deepcopy(self.base_graph)
        self.turn = 0
        self.max_turns = 40
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

        self._log("Simulation initialized. All systems safe.")

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
        red_msg = self._resolve_attack(red_action)
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
            self._log("[GAME OVER] Max turns reached.")
        
        terminations = {"red_agent": terminated, "blue_agent": terminated, "__all__": terminated}
        truncations = {"red_agent": truncated, "blue_agent": truncated, "__all__": truncated}
        
        observations = {
            "red_agent": self._get_red_observation(),
            "blue_agent": self._get_blue_observation()
        }
        
        return observations, rewards, terminations, truncations, {"turn": self.turn, "score": self.score}

    def _calculate_rewards(self) -> int:
        """Calculates score change based on un-isolated attacker access."""
        reward_delta = 0
        for node, level in self.attacker_access.items():
            if self.graph.nodes[node]["status"] == "isolated":
                continue
                
            val = self.graph.nodes[node].get("value", 0)
            if val > 0:
                reward_delta += (val * (2 if level == "root" else 1))
            else:
                reward_delta += (15 if level == "root" else 5)
                
        self.score += reward_delta
        return reward_delta

    def _check_termination(self) -> tuple[bool, str]:
        """
        Checks terminal conditions:
        - Red wins if a sensitive host is compromised with root access.
        - Blue wins if all compromised nodes have been isolated (after at least 1 compromise occurred).
        """
        # 1. Attacker Win Check: Compromised crown jewels
        for node, level in self.attacker_access.items():
            if self.graph.nodes[node]["status"] != "isolated" and level == "root":
                if self.graph.nodes[node].get("value", 0) >= 100:
                    return True, f"Attacker fully breached sensitive host {node} (Red Victory)."

        # 2. Defender Win Check: All threats neutralized (only if threats actually existed)
        if len(self.attacker_access) > 0:
            active_threats = [
                n for n in self.attacker_access 
                if self.graph.nodes[n]["status"] != "isolated"
            ]
            if len(active_threats) == 0:
                return True, "Defender isolated all compromised hosts (Blue Victory)."

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

        # Fetch exploit probability if configured
        exploit_info = self.exploits.get(detail, {})
        success_prob = exploit_info.get("prob", 0.85)

        if action_type in ["exploit", "pivot"]:
            if random.random() <= success_prob:
                self.attacker_access[target] = "user"
                self.graph.nodes[target]["status"] = "compromised"
                self.graph.nodes[target]["access"] = "user"
                return f"Breach succeeded on {target} via {detail}."
            else:
                return f"Exploit attempt on {target} via {detail} failed."
                
        elif action_type == "escalate":
            if random.random() <= 0.9:
                self.attacker_access[target] = "root"
                self.graph.nodes[target]["access"] = "root"
                return f"Privilege escalated to root on {target}."
            else:
                return f"Privilege escalation attempt on {target} failed."
                
        return "Action unrecognized or blocked."

    def _resolve_defense(self, blue_action):
        if not blue_action:
            return "Defender standing by."

        action_type = blue_action[0]
        target = blue_action[1] if len(blue_action) > 1 else None

        if action_type == "isolate" and target in self.graph:
            in_edges = list(self.graph.in_edges(target))
            out_edges = list(self.graph.out_edges(target))
            self.graph.remove_edges_from(in_edges + out_edges)
            
            self.graph.nodes[target]["status"] = "isolated"
            return f"Isolated node {target}. Ingress and egress severed."

        elif action_type == "remediate" and target in self.attacker_access:
            del self.attacker_access[target]
            self.graph.nodes[target]["status"] = "safe"
            self.graph.nodes[target]["access"] = "none"
            return f"Remediated node {target}. Malware cleared and credentials revoked."

        elif action_type == "sleep":
            return "Defender monitoring alerts (no intervention)."

        return None

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
            "turn": self.turn
        }