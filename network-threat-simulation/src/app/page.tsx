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

type RunMetrics = {
  compromised_hosts: number;
  encrypted_hosts: number;
  ever_encrypted_hosts: number;
  unavailable_host_turns: number;
  first_detection_turn: number | null;
  recovered_hosts: number;
};
type RunResult = { scenario: string; seed: number; outcome: string; metrics: RunMetrics; score: number };

export default function CyberSimulationDashboard() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [eventLog, setEventLog] = useState<string[]>([]);
  const [score, setScore] = useState(0);
  const [turn, setTurn] = useState(0);
  const [result, setResult] = useState<RunResult | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [comparisons, setComparisons] = useState<Record<string, RunResult>>({});
  const activeCommand = useRef('');

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
      setResult(data);
      if (data.outcome !== 'Running' && activeCommand.current) {
        setIsRunning(false);
        setComparisons(previous => ({ ...previous, [activeCommand.current]: data }));
      }
    };
    ws.onerror = () => { setIsRunning(false); setEventLog(['[SYSTEM] Connection failed. Check the simulation server.']); };
    ws.onclose = () => setIsRunning(false);

    return () => ws.close();
  }, []);

  const triggerSimulation = (command: string, logMsg: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      activeCommand.current = command;
      setIsRunning(true);
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
          <p>Turn: {turn}</p>
          <p className={score > 0 ? styles.scoreRed : styles.scoreBlue}>
            Cumulative impact: {score}
          </p>
          {result?.metrics && <div>
            <p>{result.outcome} · Seed {result.seed}</p>
            <p>Hosts breached: {result.metrics.compromised_hosts}</p>
            <p>Encrypted: {result.metrics.encrypted_hosts} current / {result.metrics.ever_encrypted_hosts} total</p>
            <p>Unavailable host-turns: {result.metrics.unavailable_host_turns}</p>
            <p>First response: {result.metrics.first_detection_turn ?? 'None'} · Restored: {result.metrics.recovered_hosts}</p>
          </div>}

          {/* APT Controls */}
          <div className={styles.controlSection}>
            <h3 className={styles.sectionTitle}>Advanced Persistent Threat (APT)</h3>
            <div className={styles.buttonGroup}>
              <button
                className={styles.startButton}
                disabled={isRunning}
                onClick={() => triggerSimulation('killchain_defended', '[SYSTEM] APT Attack: Blue AI Defending.')}
              >
                Defended
              </button>
              <button
                className={styles.unhinderedButton}
                disabled={isRunning}
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
                disabled={isRunning}
                onClick={() => triggerSimulation('ransomware_defended', '[SYSTEM] Ransomware: Blue AI Defending.')}
              >
                Defended
              </button>
              <button
                className={styles.unhinderedButton}
                disabled={isRunning}
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
        <h2>Completed run comparison</h2>
        <p>Both modes use seed 42. Downtime counts encrypted and isolated hosts each turn.</p>
        {(['killchain', 'ransomware'] as const).map(scenario => (
          <div key={scenario}>
            <h3>{scenario === 'killchain' ? 'APT' : 'Ransomware'}</h3>
            <table className={styles.comparisonTable}>
              <thead><tr><th>Mode</th><th>Impact</th><th>Encrypted total</th><th>Downtime</th></tr></thead>
              <tbody>{(['defended', 'unhindered'] as const).map(mode => {
                const completed = comparisons[`${scenario}_${mode}`];
                return <tr key={mode}><td>{mode}</td><td>{completed?.score ?? '—'}</td>
                  <td>{completed?.metrics.ever_encrypted_hosts ?? '—'}</td>
                  <td>{completed?.metrics.unavailable_host_turns ?? '—'}</td></tr>;
              })}</tbody>
            </table>
          </div>
        ))}
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
