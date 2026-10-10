"""Shared configuration-backed attack eligibility rules."""

def exploits_for(config, graph, target, allowed):
    host = graph.nodes[target]
    return [(name, rule) for name, rule in config.get('exploits', {}).items()
            if rule['service'] in host.get('services', [])
            and ('internal_traffic' in allowed or rule['service'] in allowed)
            and rule.get('os') in (None, 'None', host.get('os'))
            and rule.get('prob', 0) > 0]

def escalation_for(config, graph, target):
    host = graph.nodes[target]
    return next((name for name, rule in config.get('privilege_escalation', {}).items()
                 if rule.get('process') in host.get('processes', [])
                 and rule.get('os') in (None, 'None', host.get('os'))
                 and rule.get('prob', 0) > 0), None)
