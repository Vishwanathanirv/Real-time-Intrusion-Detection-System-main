import React, { useState, useEffect } from "react";
import {
  LineChart, Line, PieChart, Pie, BarChart, Bar, Cell, Tooltip, ResponsiveContainer, Legend, CartesianGrid, XAxis, YAxis,
} from "recharts";
import "./Dashboard.css";

const COLORS = ["#00C49F", "#FFBB28", "#FF8042", "#0088FE", "#FF66CC", "#33CCFF", "#AA66FF"];

const PROTOCOL_MAP = {
  1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
};

const PacketEyePro_Dashboard = () => {
  const [summary, setSummary] = useState(null);
  const [protocolData, setProtocolData] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [attackData, setAttackData] = useState([]);
  const [quantumFeatures, setQuantumFeatures] = useState([]);
  const [darkMode, setDarkMode] = useState(false);
  const [lastUpdated, setLastUpdated] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [summaryRes, protocolRes, timelineRes, attackRes, featuresRes] = await Promise.all([
          fetch("http://localhost:8080/api/packets/summary"),
          fetch("http://localhost:8080/api/packets/protocol-summary"),
          fetch("http://localhost:8080/api/packets/timeline"),
          fetch("http://localhost:8080/api/packets/attack-summary"),
          fetch("http://localhost:8080/api/packets/features"),
        ]);

        setSummary(await summaryRes.json());

        const protocolJson = await protocolRes.json();
        setProtocolData(protocolJson.map((p) => ({
          ...p,
          protocol: PROTOCOL_MAP[p.protocol] || `Unknown (${p.protocol})`,
        })));

        setTimelineData(processTimeline(await timelineRes.json()));
        setAttackData(await attackRes.json());
        setQuantumFeatures(await featuresRes.json());

        setLastUpdated(new Date().toLocaleTimeString());
      } catch (err) {
        console.error("Error fetching dashboard data:", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const processTimeline = (data) => {
    const grouped = {};
    data.forEach((pkt) => {
      const t = pkt.timestamp?.split("T")[1]?.slice(0, 8) || pkt.timestamp;
      if (!grouped[t]) grouped[t] = { t, count: 0, anomalies: 0 };
      grouped[t].count += 1;
      if (pkt.status === "Anomaly") grouped[t].anomalies += 1;
    });
    return Object.values(grouped).reverse();
  };

  if (!summary) return <div className="loading-text">Loading Analytics...</div>;

  return (
    <div className={`dashboard ${darkMode ? "dark" : "light"}`}>
      <div className="dashboard-header">
        <h1>Chanakya Shield Analytics</h1>
        <div className="header-controls">
          <p className="last-updated">Last Updated: {lastUpdated}</p>
        </div>
      </div>

      <div className="kpi-container">
        <KpiCard label="Total Packets" value={summary.totalPackets} color="#007bff" />
        <KpiCard label="Normal Traffic" value={summary.normalPackets} color="#28a745" />
        <KpiCard label="Anomalies" value={summary.anomalyPackets} color="#ffc107" />
        <KpiCard label="Attacks Detected" value={summary.totalAttacks} color="#dc3545" />
        <KpiCard label="Anomaly Rate" value={`${summary.anomalyRate}%`} color="#6f42c1" />
      </div>

      <div className="dashboard-grid">
        {/* QUANTUM FEATURES CARD */}
        <div className="chart-container features-card">
          <h2>Quantum Optimized Features</h2>
          <div className="features-list">
            {quantumFeatures.length > 0 ? (
              <ul>
                {quantumFeatures.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            ) : (
              <p>No features loaded.</p>
            )}
          </div>
          <div className="feature-status">
            <span>Algorithm: QUBO (Simulated Annealing)</span>
            <span>Selection: Optimized for Accuracy</span>
          </div>
        </div>

        <div className="chart-container">
          <h2>Traffic Timeline</h2>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="t" tick={{ fontSize: 10 }} />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#007bff" name="Total Packets" dot={false} />
                <Line type="monotone" dataKey="anomalies" stroke="#dc3545" name="Anomalies" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : <p className="no-data">No data available</p>}
        </div>

        <div className="chart-container">
          <h2>Protocol Distribution</h2>
          {protocolData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie data={protocolData} dataKey="count" nameKey="protocol" cx="50%" cy="50%" outerRadius={80} label>
                  {protocolData.map((_, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="no-data">No data available</p>}
        </div>

        <div className="chart-container">
          <h2>Attack Classification</h2>
          {attackData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={attackData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="attack" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" fill="#dc3545" name="Count">
                  {attackData.map((_, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="no-data">No data available</p>}
        </div>
      </div>
    </div>
  );
};

const KpiCard = ({ label, value, color }) => (
  <div className="kpi-card" style={{ borderTop: `4px solid ${color}` }}>
    <h3>{label}</h3>
    <p style={{ color }}>{value}</p>
  </div>
);

export default PacketEyePro_Dashboard;