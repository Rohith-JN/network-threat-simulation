import heapq
import networkx as nx

class AdvancedRedAgent:
    def __init__(self, config: dict):
        self.exploits = config.get("exploits", {})
        self.priv_esc = config.get("privilege_escalation", {})
        
        # Identify the 100-point targets from the YAML
        sensitive_raw = config.get("sensitive_hosts", {})
        self.targets = [str(eval(k)) if isinstance(k, str) else str(tuple(k)) for k in sensitive_raw.keys()]

    def get_optimal_attack_step(self, graph: nx.DiGraph, attacker_access: dict):
        """
        Calculates the shortest path to a sensitive host and returns the next action.
        """
        if not attacker_access:
            return ("exploit", "(1, 0)", "http") # Fixed entry point for initial breach

        # 1. Identify starting nodes (where the attacker currently has root)
        start_nodes = [node for node, access in attacker_access.items() if access == "root"]
        
        if not start_nodes:
            # Need to escalate privilege before moving laterally
            for node, access in attacker_access.items():
                if access == "user":
                    return ("escalate", node, None)
                    
        # 2. Run Dijkstra's Algorithm from all root-compromised nodes
        shortest_path = self._run_dijkstra(graph, start_nodes)
        
        if shortest_path:
            # The path returns a list of nodes e.g., ['(1, 0)', '(2, 0)', '(3, 1)']
            # The next step is the first uncompromised node in the sequence
            next_target = shortest_path[1] 
            
            # Determine which service to exploit based on firewall edges
            edge_data = graph.get_edge_data(shortest_path[0], next_target)
            allowed = edge_data.get("allowed_services", [])
            target_services = graph.nodes[next_target].get("services", [])
            
            # Pick a valid service to target
            for svc in target_services:
                if svc in allowed or "internal_traffic" in allowed:
                    return ("pivot", next_target, svc)
                    
        return ("sleep", None) # No valid path found (Defender won)

    def _run_dijkstra(self, graph: nx.DiGraph, start_nodes: list) -> list:
        """
        Standard Dijkstra implementation using a priority queue.
        Finds the lowest-cost path from any start_node to any sensitive target.
        """
        # Priority Queue: stores tuples of (total_cost, current_node, path_history)
        pq = []
        for start in start_nodes:
            heapq.heappush(pq, (0, start, [start]))
            
        visited = set()
        
        while pq:
            current_cost, current_node, path = heapq.heappop(pq)
            
            # Control Flow: Goal Check
            if current_node in self.targets and current_node not in start_nodes:
                return path 
                
            if current_node in visited:
                continue
            visited.add(current_node)
            
            # Control Flow: Explore Neighbors
            for neighbor in graph.successors(current_node):
                if neighbor in visited or graph.nodes[neighbor]["status"] == "isolated":
                    continue
                    
                edge_cost = self._calculate_edge_cost(graph, current_node, neighbor)
                
                if edge_cost < float('inf'):
                    new_cost = current_cost + edge_cost
                    new_path = list(path)
                    new_path.append(neighbor)
                    heapq.heappush(pq, (new_cost, neighbor, new_path))
                    
        return None # Target unreachable

    def _calculate_edge_cost(self, graph, u, v) -> float:
        """Calculates traversal weight based on exploit costs."""
        edge_data = graph.get_edge_data(u, v)
        allowed = edge_data.get("allowed_services", [])
        target_services = graph.nodes[v].get("services", [])
        
        # Check if the firewall allows connection to a running service
        valid_services = [s for s in target_services if s in allowed or "internal_traffic" in allowed]
        if not valid_services:
            return float('inf') # Wall detected
            
        # Find the cheapest exploit for the available services
        min_cost = float('inf')
        for exp_name, exp_data in self.exploits.items():
            if exp_data["service"] in valid_services:
                if exp_data["cost"] < min_cost:
                    min_cost = exp_data["cost"]
                    
        return min_cost