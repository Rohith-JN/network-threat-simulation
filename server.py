import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from build_semantic_net import parse_nasim_yaml
from engine import MultiAgentCyberEngine
# 1. Import the RansomwareAgent
from red_agent import HybridRedAgent, BotnetAgent, RansomwareAgent
from blue_agent import HybridBlueAgent

app = FastAPI()

@app.websocket("/ws/simulation")
async def simulation_endpoint(websocket: WebSocket):
    await websocket.accept()
    graph, config = parse_nasim_yaml("tiny.yaml")
    
    try:
        while True:
            msg = await websocket.receive_text()
            
            # 2. Add the ransomware commands to the listener
            valid_commands = [
                "killchain_defended", "killchain_unhindered", 
                "ddos_defended", "ddos_unhindered",
                "ransomware_defended", "ransomware_unhindered"
            ]
            
            if msg in valid_commands:
                env = MultiAgentCyberEngine(graph, config)

                if msg == "init":
                    await websocket.send_json(env.export_xyflow_json())
                    continue
                
                # 3. Assign the correct Attacker AI
                if "ddos" in msg:
                    red_ai = BotnetAgent(config)
                elif "ransomware" in msg:
                    red_ai = RansomwareAgent(config)
                else:
                    red_ai = HybridRedAgent(config)
                    
                blue_ai = HybridBlueAgent()
                observations, _ = env.reset()
                done = False
                
                await websocket.send_json(env.export_xyflow_json())
                await asyncio.sleep(1)
                
                while not done and env.turn < 21:
                    red_action = red_ai.get_optimal_attack_step(env.graph, env.attacker_access)
                    
                    if "unhindered" in msg:
                        blue_action = ("sleep", None)
                    else:
                        blue_action = blue_ai.get_action(env, observations["blue_agent"], red_ai)

                    # --- NEW: Process simultaneous worm attacks ---
                    if isinstance(red_action, list):
                        for action in red_action:
                            observations, _, term, trunc, _ = env.step({
                                "red_agent": action,
                                "blue_agent": ("sleep", None) # Blue waits until Red finishes spreading
                            })
                        # Let Blue take its defensive turn after the wave
                        observations, _, term, trunc, _ = env.step({
                            "red_agent": ("sleep", None),
                            "blue_agent": blue_action
                        })
                    else:
                        # Standard single action for APT / Botnet
                        observations, _, term, trunc, _ = env.step({
                            "red_agent": red_action,
                            "blue_agent": blue_action
                        })
                    # ----------------------------------------------
                    
                    await websocket.send_json(env.export_xyflow_json())
                    
                    # --- NEW: Ignore early Game Over for Ransomware ---
                    done = term["__all__"] or trunc["__all__"]
                    
                    # Only ignore the Game Over flag if we want the worm to spread freely
                    if msg == "ransomware_unhindered":
                        done = False
                        
                    await asyncio.sleep(1.5)
                    
    except WebSocketDisconnect:
        print("Client disconnected.")