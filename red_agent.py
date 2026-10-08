import networkx as nx
import random

class HybridRedAgent:
    def __init__(self, config):
        self.config = config
        self.exploits = config.get("exploits", {})
        self.target_node = None 

    def get_optimal_attack_step(self, graph: nx.DiGraph, attacker_access: dict):
        if not self.target_node:
            high_score = -1
            for n, d in graph.nodes(data=True):
                if d.get("value", 0) > high_score:
                    high_score = d.get("value", 0)
                    self.target_node = n

        # 1. RANDOMIZED ENTRY POINT
        if not attacker_access:
            # Find all nodes in Subnet 1 (the DMZ/outer edge)
            entry_points = [n for n, d in graph.nodes(data=True) if d.get("subnet") == 1]
            if not entry_points: 
                entry_points = list(graph.nodes) # Fallback
            
            entry = random.choice(entry_points)
            return ("exploit", entry, "http")

        # 2. PROBABILISTIC DIJKSTRA WITH JITTER
        weighted_graph = graph.copy()
        for u, v, data in weighted_graph.edges(data=True):
            success_prob = 0.85
            if "allowed_services" in data and len(data["allowed_services"]) > 0:
                svc = data["allowed_services"][0]
                success_prob = self.exploits.get(svc, {}).get("prob", 0.85)
            
            # Inject a tiny random "noise" factor (0.0 to 0.3) to the weight
            # This makes the AI occasionally pick a different path if costs are similar
            noise = random.uniform(0.0, 0.3)
            weighted_graph[u][v]['weight'] = (1.0 / success_prob) + noise

        best_path = None
        current_foothold = None

        for node, access in attacker_access.items():
            if graph.nodes[node].get("status") == "isolated":
                continue
            try:
                path = nx.shortest_path(weighted_graph, source=node, target=self.target_node, weight='weight')
                if not best_path or len(path) < len(best_path):
                    best_path = path
                    current_foothold = node
            except nx.NetworkXNoPath:
                continue

        if not best_path:
            return ("sleep", None, None)

        # 3. ENFORCE KILL CHAIN
        current_access = attacker_access[current_foothold]
        
        if len(best_path) == 1:
            if current_access != "root":
                return ("escalate", current_foothold, None)
            return ("sleep", None, None)

        next_hop = best_path[1]
        
        if current_access != "root":
            return ("escalate", current_foothold, None)
        else:
            return ("pivot", next_hop, "smb")


class BotnetAgent:
    def __init__(self, config):
        self.config = config

    def get_optimal_attack_step(self, graph, attacker_access):
        # Locate all servers in the DMZ that are not already offline or isolated
        dmz_nodes = [
            n for n, d in graph.nodes(data=True) 
            if d.get("subnet") == 1 and d.get("status") not in ["offline", "isolated"]
        ]
        
        if dmz_nodes:
            # Pick a random target to flood
            target = random.choice(dmz_nodes)
            return ("ddos", target, "syn_flood")
            
        # If all DMZ nodes are down, the botnet goes to sleep
        return ("sleep", None, None)

class RansomwareAgent:
    def __init__(self, config):
        self.config = config

    def get_optimal_attack_step(self, graph, attacker_access):
        actions = []
        
        # 1. Initial Foothold
        if not attacker_access:
            entry_points = [n for n, d in graph.nodes(data=True) if d.get("subnet") == 1]
            if entry_points: 
                import random
                actions.append(("exploit", random.choice(entry_points), "http"))
            return actions

        # 2. Encrypt all currently owned nodes
        for node, access in list(attacker_access.items()):
            if graph.nodes[node].get("status") not in ["encrypted", "isolated"]:
                if access == "root":
                    actions.append(("ransomware", node, None))
                else:
                    actions.append(("escalate", node, None))
        
        # 3. Viral Spread (Breadth-First Expansion)
        # Simultaneously pivot to EVERY connected neighbor that isn't infected
        for node in attacker_access.keys():
            for neighbor in graph.neighbors(node):
                if neighbor not in attacker_access and graph.nodes[neighbor].get("status") != "isolated":
                    # Prevent duplicate commands to the same node
                    if not any(a[1] == neighbor for a in actions):
                        actions.append(("pivot", neighbor, "smb"))
                        
        if not actions:
            actions.append(("sleep", None, None))
            
        return actions
    def __init__(self, config):
        self.config = config

    def get_optimal_attack_step(self, graph, attacker_access):
        # 1. Initial Foothold
        if not attacker_access:
            entry_points = [n for n, d in graph.nodes(data=True) if d.get("subnet") == 1]
            if not entry_points: 
                entry_points = list(graph.nodes)
            import random
            entry = random.choice(entry_points)
            return ("exploit", entry, "http")

        # 2. Encrypt Current Assets
        # If we have access to a node and it isn't encrypted yet, lock it down!
        for node, access in attacker_access.items():
            if graph.nodes[node].get("status") not in ["encrypted", "isolated"]:
                if access == "root":
                    return ("ransomware", node, None)
                else:
                    return ("escalate", node, None)
        
        # 3. Worm Spread (Breadth-First Expansion)
        # If all currently owned nodes are encrypted, aggressively pivot to adjacent neighbors
        for node in attacker_access.keys():
            for neighbor in graph.neighbors(node):
                if neighbor not in attacker_access and graph.nodes[neighbor].get("status") != "isolated":
                    return ("pivot", neighbor, "smb")
                    
        return ("sleep", None, None)