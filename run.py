import time
from build_semantic_net import parse_nasim_yaml
from engine import MultiAgentCyberEngine
from red_agent import HybridRedAgent
from blue_agent import HybridBlueAgent

def run_simulation():
    graph, config = parse_nasim_yaml("network.yaml")
    env = MultiAgentCyberEngine(graph, config)
    
    red_ai = HybridRedAgent(config)
    blue_ai = HybridBlueAgent()

    observations, _ = env.reset()
    done = False
    
    print("=" * 70)
    print("HYBRID AI SIMULATION: BAYESIAN-MINIMAX VS ATTACK-TREE-DIJKSTRA")
    print("=" * 70)

    while not done and env.turn < 20:
        print(f"\n--- Turn {env.turn + 1} ---")
        
        # 1. Red calculates Probabilistic Dijkstra + Attack Tree
        red_access = env.attacker_access
        red_action = red_ai.get_optimal_attack_step(env.graph, red_access)
        
        # 2. Blue calculates Bayesian Belief + Minimax Strategy
        blue_action = blue_ai.get_action(env, observations["blue_agent"], red_ai)
        
        # 3. Resolve the physics
        next_obs, rewards, term, trunc, info = env.step({
            "red_agent": red_action,
            "blue_agent": blue_action
        })
        
        print(f"  [RED AI] Chosen Move: {red_action} | Score: {rewards['red_agent']}")
        print(f"  [BLUE AI] Chosen Move: {blue_action} | Score: {rewards['blue_agent']}")
        
        observations = next_obs
        done = term["__all__"] or trunc["__all__"]
        time.sleep(1)

    print("\nSimulation Concluded.")

if __name__ == "__main__":
    run_simulation()