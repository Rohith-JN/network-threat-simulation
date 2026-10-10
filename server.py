import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from build_semantic_net import parse_nasim_yaml
from engine import MultiAgentCyberEngine
from red_agent import HybridRedAgent, RansomwareAgent
from blue_agent import HybridBlueAgent

app = FastAPI()


@app.websocket("/ws/simulation")
async def simulation_endpoint(websocket: WebSocket):
    await websocket.accept()
    graph, config = parse_nasim_yaml("network.yaml")
    commands = {"killchain_defended", "killchain_unhindered",
                "ransomware_defended", "ransomware_unhindered"}
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "init":
                env = MultiAgentCyberEngine(graph, config)
                env.reset()
                await websocket.send_json(env.export_xyflow_json())
                continue
            if msg not in commands:
                continue
            scenario = msg.split("_")[0]
            # Both modes restart with identical initial conditions and seed.
            env = MultiAgentCyberEngine(graph, config, scenario=scenario, seed=42)
            agent = RansomwareAgent if scenario == "ransomware" else HybridRedAgent
            red_ai = agent(config, seed=42)
            blue_ai = HybridBlueAgent()
            observations, _ = env.reset()
            await websocket.send_json(env.export_xyflow_json())
            done = False
            while not done:
                # Lookahead uses private copies; it cannot advance the live attacker.
                blue_action = (("sleep", None) if msg.endswith("unhindered") else
                               blue_ai.get_action(env, observations["blue_agent"], red_ai))
                red_action = red_ai.get_optimal_attack_step(env.graph, env.attacker_access)
                observations, _, term, trunc, _ = env.step({
                    "red_agent": red_action, "blue_agent": blue_action})
                await websocket.send_json(env.export_xyflow_json())
                done = term["__all__"] or trunc["__all__"]
                if not done:
                    await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
