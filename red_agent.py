import random
import networkx as nx
from attack_rules import exploits_for, escalation_for


class HybridRedAgent:
    def __init__(self, config, seed=42):
        self.config = config
        self.rng = random.Random(seed)

    def entry_action(self, graph):
        candidates = []
        for node, data in graph.nodes(data=True):
            if data.get('subnet') != 1 or data.get('status') == 'isolated':
                continue
            if not graph.has_edge('(0, 0)', node):
                continue
            for name, _ in exploits_for(self.config, graph, node,
                                        graph.edges['(0, 0)', node]['allowed_services']):
                candidates.append(('exploit', node, name))
        return self.rng.choice(candidates) if candidates else ('sleep', None, None)

    def attack_graph(self, graph):
        weighted = nx.DiGraph()
        weighted.add_nodes_from(n for n, d in graph.nodes(data=True)
                                if d.get('status') != 'isolated' and d.get('subnet') != 0)
        for source, target, data in graph.edges(data=True):
            if source not in weighted or target not in weighted:
                continue
            rules = exploits_for(self.config, graph, target, data.get('allowed_services', []))
            if rules:
                name, rule = max(rules, key=lambda item: item[1]['prob'])
                weighted.add_edge(source, target, exploit=name,
                                  weight=1 / rule['prob'] + self.rng.uniform(0, 0.1))
        return weighted

    def get_optimal_attack_step(self, graph, attacker_access):
        if not attacker_access:
            return self.entry_action(graph)
        weighted = self.attack_graph(graph)
        targets = sorted((n for n in weighted if graph.nodes[n].get('value', 0) >= 100),
                         key=lambda n: graph.nodes[n]['value'], reverse=True)
        paths = []
        for target in targets:
            for source in attacker_access:
                if source not in weighted:
                    continue
                try:
                    path = nx.shortest_path(weighted, source, target, weight='weight')
                    cost = nx.path_weight(weighted, path, 'weight') if len(path) > 1 else 0
                    paths.append((cost, path))
                except nx.NetworkXNoPath:
                    pass
            if paths:
                break
        if not paths:
            return ('sleep', None, None)
        _, path = min(paths, key=lambda item: item[0])
        source = path[0]
        escalation = escalation_for(self.config, graph, source)
        if attacker_access[source] != 'root' and escalation:
            return ('escalate', source, escalation)
        if len(path) > 1:
            target = path[1]
            return ('pivot', target, weighted.edges[source, target]['exploit'], source)
        return ('sleep', None, None)


class RansomwareAgent(HybridRedAgent):
    """One wave per turn, using only footholds present at its start."""
    def get_optimal_attack_step(self, graph, attacker_access):
        if not attacker_access:
            return [self.entry_action(graph)]
        actions = []
        weighted = self.attack_graph(graph)
        scheduled = set()
        for node, access in attacker_access.items():
            if node not in weighted:
                continue
            if graph.nodes[node].get('status') != 'encrypted':
                escalation = escalation_for(self.config, graph, node)
                if access == 'root':
                    actions.append(('ransomware', node, None))
                elif escalation:
                    actions.append(('escalate', node, escalation))
            for neighbor in weighted.successors(node):
                if neighbor not in attacker_access and neighbor not in scheduled:
                    actions.append(('pivot', neighbor, weighted.edges[node, neighbor]['exploit'], node))
                    scheduled.add(neighbor)
        return actions or [('sleep', None, None)]
