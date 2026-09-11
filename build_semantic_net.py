import yaml
import networkx as nx
import ast

def parse_nasim_yaml(filepath: str) -> nx.DiGraph:
    with open(filepath, "r") as f:
        config = yaml.safe_load(f)

    # Directed graph because firewall connections are directional
    G = nx.DiGraph()

    # 1. Parse Sensitive Hosts (targets with high value)
    sensitive_raw = config.get("sensitive_hosts", {})
    sensitive_dict = {}
    for k, val in sensitive_raw.items():
        parsed_key = ast.literal_eval(k) if isinstance(k, str) else tuple(k)
        sensitive_dict[parsed_key] = val

    # 2. Add Host Nodes with attributes
    host_configs = config.get("host_configurations", {})
    for host_key, attrs in host_configs.items():
        node_id = ast.literal_eval(host_key) if isinstance(host_key, str) else tuple(host_key)
        subnet_id, host_num = node_id

        G.add_node(
            str(node_id),
            subnet=subnet_id,
            host_idx=host_num,
            os=attrs.get("os", "unknown"),
            services=attrs.get("services", []),
            processes=attrs.get("processes", []),
            value=sensitive_dict.get(node_id, 0),
            status="safe"  # initial status: safe | suspicious | compromised | isolated
        )

    # 3. Add Internet Gateway Node (Subnet 0)
    internet_node = "(0, 0)"
    G.add_node(internet_node, subnet=0, host_idx=0, os="none", services=[], processes=[], value=0, status="internet")

    # 4. Parse Firewall Rules & Build Edges
    firewall = config.get("firewall", {})
    subnets_hosts = {}
    for n, d in G.nodes(data=True):
        subnets_hosts.setdefault(d["subnet"], []).append(n)

    for connection_key, allowed_services in firewall.items():
        if not allowed_services:
            continue
        
        pair = ast.literal_eval(connection_key) if isinstance(connection_key, str) else tuple(connection_key)
        src_subnet, dst_subnet = pair

        src_nodes = subnets_hosts.get(src_subnet, [])
        dst_nodes = subnets_hosts.get(dst_subnet, [])

        for u in src_nodes:
            for v in dst_nodes:
                if u != v:
                    G.add_edge(u, v, allowed_services=allowed_services)

    # Allow intra-subnet communication (hosts on the same subnet talk directly)
    for subnet_id, hosts in subnets_hosts.items():
        if subnet_id == 0:
            continue
        for u in hosts:
            for v in hosts:
                if u != v:
                    G.add_edge(u, v, allowed_services=["internal_traffic"])

    return G, config

if __name__ == "__main__":
    graph, config = parse_nasim_yaml("medium.yaml")
    
    print(f"Graph loaded successfully!")
    print(f"Total Nodes: {graph.number_of_nodes()}")
    print(f"Total Directed Edges: {graph.number_of_edges()}")
    
    # Inspect entry point
    entry = "(1, 0)"
    print(f"\nEntry Host {entry} attributes: {graph.nodes[entry]}")
    print(f"Incoming edges to {entry}: {list(graph.in_edges(entry, data=True))}")