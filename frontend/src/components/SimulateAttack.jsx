import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import "./SimulateAttack.css";

const SimulateAttack = () => {
  const navigate = useNavigate();
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [activeAttack, setActiveAttack] = useState("");

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch("http://localhost:8080/api/status");
        const data = await res.json();
        setIsRunning(data.simulation && data.simulation.includes("Running"));
      } catch (err) {
        console.error("Error fetching simulation status:", err);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const startSimulation = async (attackType = "") => {
    setIsStarting(true);
    setActiveAttack(attackType || "all");
    try {
      const url = attackType 
        ? `http://localhost:8080/api/simulate-attack?type=${attackType}`
        : "http://localhost:8080/api/simulate-attack";
      const res = await fetch(url);
      const text = await res.text();
      setIsRunning(true);
    } catch (err) {
      console.error("Failed to start simulation:", err);
    } finally {
      setIsStarting(false);
    }
  };

  const stopSimulation = async () => {
    setIsStopping(true);
    try {
      const res = await fetch("http://localhost:8080/api/stop-simulation");
      setIsRunning(false);
      setActiveAttack("");
    } catch (err) {
      console.error("Failed to stop simulation:", err);
    } finally {
      setIsStopping(false);
    }
  };

  const attackTypes = [
    { id: "ddos", name: "DDoS Attack", icon: "🌊", color: "#ff4444" },
    { id: "portscan", name: "Port Scan", icon: "🔍", color: "#ff6b35" },
    { id: "dos-hulk", name: "DoS Hulk", icon: "💥", color: "#f7931e" },
    { id: "ssh", name: "SSH Brute Force", icon: "🔐", color: "#fbb034" },
    { id: "web", name: "Web Attack", icon: "🌐", color: "#ffca3a" },
    { id: "bot", name: "Botnet Traffic", icon: "🤖", color: "#ff85a1" },
    { id: "benign", name: "Benign Traffic", icon: "✅", color: "#00d084" },
  ];

  return (
    <div className="simulate-container">
      <h2>THREAT SIMULATION</h2>
      <p>
        Initiate controlled cyber attacks using specialized injection engines.
      </p>

      <div className="control-panel">
        <div className="attack-grid">
          {attackTypes.map((attack) => (
            <button
              key={attack.id}
              className="attack-btn"
              style={{ borderColor: attack.color }}
              onClick={() => startSimulation(attack.id)}
              disabled={isStarting || isRunning}
            >
              <span className="attack-icon" style={{ color: attack.color }}>
                {attack.icon}
              </span>
              <span className="attack-name">{attack.name}</span>
            </button>
          ))}
        </div>

        <div className="all-attacks-section">
          <button
            className="simulate-btn start"
            onClick={() => startSimulation()}
            disabled={isStarting || isRunning}
          >
            {isStarting ? "INITIALIZING..." : "🎯 RUN ALL ATTACKS"}
          </button>

          <button
            className="simulate-btn stop"
            onClick={stopSimulation}
            disabled={!isRunning || isStopping}
          >
            {isStopping ? "TERMINATING..." : "⛔ ABORT SIMULATION"}
          </button>
        </div>

        <div className="terminal-status">
          <span className="terminal-line typing-cursor">
            STATUS: {isRunning 
              ? `SIMULATING ${activeAttack.toUpperCase()} - INJECTING PACKETS...` 
              : "SYSTEM STANDBY - READY"}
          </span>
        </div>
      </div>
    </div>
  );
};

export default SimulateAttack;