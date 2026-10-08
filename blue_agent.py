import copy
import re

class HybridBlueAgent:
    def __init__(self):
        # Bayesian Belief State: Tracks threat probability per node
        self.belief_state = {}

    def _bayesian_update(self, event_log):
        """Phase 1: The Observer. Updates threat probabilities based on noisy logs."""
        for log in event_log:
            # Simulate parsing an IDS alert or failed login
            if "Breach succeeded on" in log or "Exploit attempt on" in log:
                # Extract the node tuple string like '(1, 0)'
                match = re.search(r"\((\d+),\s*(\d+)\)", log)
                if match:
                    node = f"({match.group(1)}, {match.group(2)})"
                    current_prob = self.belief_state.get(node, 0.0)
                    
                    if "succeeded" in log:
                        self.belief_state[node] = min(1.0, current_prob + 0.95) # High confidence
                    elif "failed" in log:
                        self.belief_state[node] = min(1.0, current_prob + 0.40) # Suspicious noise
                        
    def get_action(self, current_env, obs, red_ai):
        """Phase 2: The Strategist. Runs Minimax on the hallucinated belief state."""
        # 1. Update beliefs based on the latest telemetry
        self._bayesian_update(obs.get("event_log", []))
        
        # 2. Build a "Hallucinated" Environment based on our beliefs
        # Blue doesn't know Red's true access, it only guesses based on probabilities > 80%
        sim_env = copy.deepcopy(current_env)
        sim_env.attacker_access = {} 
        
        for node, prob in self.belief_state.items():
            if prob > 0.80 and sim_env.graph.nodes[node]["status"] != "isolated":
                sim_env.attacker_access[node] = "user"
                
        # 3. Generate legal moves based on the hallucinated threats
        valid_actions = [("sleep", None)]
        for node in sim_env.attacker_access.keys():
            valid_actions.append(("isolate", node))
            valid_actions.append(("remediate", node))


        # --- NEW: Responses to availability attacks ---
        for node, data in sim_env.graph.nodes(data=True):
            if data.get("status") == "offline":
                valid_actions.append(("mitigate_ddos", node))

        for node in sim_env.attacker_access.keys():
            valid_actions.append(("isolate", node))
            valid_actions.append(("remediate", node))
            
        # --- NEW: Response to Ransomware ---
        for node, data in sim_env.graph.nodes(data=True):
            if data.get("status") == "encrypted":
                valid_actions.append(("restore_backup", node))

        # 4. Depth-1 Minimax Lookahead
        best_action = ("sleep", None)
        best_eval = float('-inf')

        for blue_action in valid_actions:
            hypothetical_env = copy.deepcopy(sim_env)
            hypothetical_env._resolve_defense(blue_action)
            
            # Predict Red's response using the Red Agent's logic
            sim_red_action = red_ai.get_optimal_attack_step(hypothetical_env.graph, hypothetical_env.attacker_access)
            hypothetical_env._resolve_attack(sim_red_action)
            
            score_delta = hypothetical_env._calculate_rewards()
            blue_eval = -hypothetical_env.score 

            if blue_eval > best_eval:
                best_eval = blue_eval
                best_action = blue_action

        return best_action