'use client';

import React, { useEffect, useState, useRef } from 'react';
import { ReactFlow, Background, Controls, Node, Edge, Handle, Position } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import styles from './page.module.css';

// 1. Define the Custom Node Component
const ServerNode = ({ data }: { data: any }) => {
  // Inside ServerNode component
  let statusClass = styles.nodeSafe;
  if (data.status === 'compromised') statusClass = styles.nodeCompromised;
  if (data.status === 'isolated') statusClass = styles.nodeIsolated;
  if (data.status === 'encrypted') statusClass = styles.nodeEncrypted;

  return (
    <div className={`${styles.customNode} ${statusClass}`}>
      <Handle type="target" position={Position.Top} className={styles.handle} />
      <div className={styles.nodeHeader}>{data.label}</div>
      <div className={styles.nodeBody}>
        <div><strong>OS:</strong> {data.os || 'Unknown'}</div>

        {data.status === 'encrypted' ? (
          <div style={{ color: '#d8b4fe', fontWeight: 'bold' }}>ENCRYPTED</div>
        ) : (
          <div><strong>Status:</strong> {data.status}</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className={styles.handle} />
    </div>
  );
};

// Register custom node type outside the main component to prevent re-rendering issues
const nodeTypes = { serverNode: ServerNode };

export default function CyberSimulationDashboard() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [eventLog, setEventLog] = useState<string[]>([]);
  const [score, setScore] = useState(0);
  const [turn, setTurn] = useState(0);

  // Store the WebSocket connection to use in the button click handler
  const wsRef = useRef<WebSocket | null>(null);

  // Inside CyberSimulationDashboard component

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws/simulation');
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send("init");
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      // Map the backend nodes to our custom 'serverNode' type
      const typedNodes = data.nodes.map((n: Node) => ({
        ...n,
        type: 'serverNode'
      }));

      setNodes(typedNodes);
      setEdges(data.edges);
      setEventLog(data.event_log);
      setScore(data.score);
      setTurn(data.turn);
    };

    return () => ws.close();
  }, []);

  const handleStartSimulation = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send("start");
      setEventLog(["[SYSTEM] Initiating defended simulation run..."]);
    }
  };

  // --- NEW: Unhindered Simulation Handler ---
  const handleStartNoDefense = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send("start_no_defense");
      setEventLog(["[SYSTEM] Initiating UNHINDERED attack run. Blue Agent offline."]);
    }
  };

  const handleStartDDoS = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send("start_ddos");
      setEventLog(["[SYSTEM] Initiating Volumetric DDoS Attack..."]);
    }
  };

  const triggerSimulation = (command: string, logMsg: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(command);
      setEventLog([logMsg]);
    }
  };

  const getLogClass = (log: string) => {
    let classes = styles.logEntry;
    if (log.includes('[RED]')) classes += ` ${styles.redAction}`;
    if (log.includes('[BLUE]')) classes += ` ${styles.blueAction}`;
    return classes;
  };

  return (
    <div className={styles.dashboardContainer}>
      <div className={styles.canvasArea}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          colorMode="dark"
        >
          <Background color="#333" gap={16} />
          <Controls />
        </ReactFlow>
        {/* Overlay HUD */}
        <div className={styles.hudOverlay}>
          <h1>Sentinel AI Defense</h1>
          <p>Turn: {turn}</p>
          <p className={score > 0 ? styles.scoreRed : styles.scoreBlue}>
            Attacker Score: {score}
          </p>

          {/* APT Controls */}
          <div className={styles.controlSection}>
            <h3 className={styles.sectionTitle}>Advanced Persistent Threat (APT)</h3>
            <div className={styles.buttonGroup}>
              <button
                className={styles.startButton}
                onClick={() => triggerSimulation('killchain_defended', '[SYSTEM] APT Attack: Blue AI Defending.')}
              >
                Defended
              </button>
              <button
                className={styles.unhinderedButton}
                onClick={() => triggerSimulation('killchain_unhindered', '[SYSTEM] APT Attack: Unhindered.')}
              >
                Unhindered
              </button>
            </div>
          </div>


          {/* --- NEW: Ransomware Controls --- */}
          <div className={styles.controlSection}>
            <h3 className={styles.sectionTitle}>Crypto-Worm (Ransomware)</h3>
            <div className={styles.buttonGroup}>
              <button
                className={styles.startButton}
                onClick={() => triggerSimulation('ransomware_defended', '[SYSTEM] Ransomware: Blue AI Defending.')}
              >
                Defended
              </button>
              <button
                className={styles.unhinderedButton}
                onClick={() => triggerSimulation('ransomware_unhindered', '[SYSTEM] Ransomware: Unhindered Spread.')}
              >
                Unhindered
              </button>
            </div>
          </div>
          {/* -------------------------------- */}

        </div>
      </div>

      <div className={styles.sidebar}>
        <h2>Telemetry Logs</h2>
        <div className={styles.logContainer}>
          {eventLog.map((log, index) => (
            <div key={index} className={getLogClass(log)}>
              {log}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}