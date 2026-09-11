import time
from build_semantic_net import parse_nasim_yaml
from engine import MultiAgentCyberEngine
from red_agent import AdvancedRedAgent
from blue_agent import SentinelBayesianBrain, get_blue_agent_action

def run_simulation():
    # 1. Initialize the Environment and Algorithms
    graph, config = parse_nasim_yaml("medium.yaml")
    env = MultiAgentCyberEngine(graph, config)
    
    red_ai = AdvancedRedAgent(config)
    blue_ai = SentinelBayesianBrain()

    observations, _ = env.reset()
    done = False
    
    print("=" * 60)
    print("ALGORITHMIC CYBER SIMULATION INITIATED")
    print("=" * 60)

    # 2. The Core Game Loop
    while not done and env.turn < 20:
        print(f"\n--- Turn {env.turn + 1} ---")
        
        # Red Agent calculates shortest path via Dijkstra
        red_access = observations["red_agent"]["attacker_access"]
        red_action = red_ai.get_optimal_attack_step(env.graph, red_access)
        
        # Blue Agent calculates threat probabilities via Bayesian Network
        blue_action = get_blue_agent_action(observations["blue_agent"], blue_ai)
        
        # Engine resolves the physics
        next_observations, rewards, terminations, truncations, info = env.step({
            "red_agent": red_action,
            "blue_agent": blue_action
        })
        
        # Logging for the backend terminal
        print(f"  [RED AI] Action: {red_action} | Score: {rewards['red_agent']}")
        print(f"  [BLUE AI] Action: {blue_action} | Score: {rewards['blue_agent']}")
        
        observations = next_observations
        done = terminations["__all__"] or truncations["__all__"]
        
        # Optional: Add a slight delay if you want to watch it run in the terminal
        time.sleep(1)

    print("\nSimulation Concluded.")

if __name__ == "__main__":
    run_simulation()