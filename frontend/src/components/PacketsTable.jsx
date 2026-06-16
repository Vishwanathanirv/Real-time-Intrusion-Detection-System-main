import React, { useEffect, useState } from "react";
import "./PacketsTable.css";

const PacketsTable = () => {
  const [packets, setPackets] = useState([]);
  const [isStopping, setIsStopping] = useState(false);
  const [isStopped, setIsStopped] = useState(false); // ✅ new state to track stop status

  useEffect(() => {
    const fetchPackets = async () => {
      try {
        const res = await fetch("http://localhost:8080/api/packets");
        const data = await res.json();
        setPackets(data);
      } catch (err) {
        console.error("Error fetching packets:", err);
      }
    };

    // only fetch if not stopped
    if (!isStopped) {
      fetchPackets();
      const interval = setInterval(fetchPackets, 3000);
      return () => clearInterval(interval);
    }
  }, [isStopped]);

  const stopCapture = async () => {
    setIsStopping(true);
    try {
      const res = await fetch("http://localhost:8080/api/stop-capture");
      const text = await res.text();
      alert(text);
      setIsStopped(true); // ✅ mark capture as stopped
    } catch (err) {
      alert("⚠️ Failed to stop packet capture!");
      console.error("Stop capture error:", err);
    } finally {
      setIsStopping(false);
    }
  };

  const clearLog = async () => {
    if (window.confirm('Are you sure you want to clear all packet logs? This action cannot be undone.')) {
      try {
        const res = await fetch('http://localhost:8080/api/packets', {
          method: 'DELETE'
        });
        const data = await res.json();
        alert(data.message || 'Packets cleared successfully!');
        setPackets([]);
      } catch (err) {
        console.error('Failed to clear packets:', err);
        alert('Failed to clear packets. Please try again.');
      }
    }
  };

  return (
    <div className="packets-container">
      <div className="header-row">
        <h2>📡 Captured Packets</h2>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            className={`stop-btn ${isStopped ? "stopped" : ""}`}
            onClick={stopCapture}
            disabled={isStopping || isStopped}
          >
            {isStopped
              ? "✅ Stopped"
              : isStopping
              ? "⏳ Stopping..."
              : "🛑 Stop Packet Capture"}
          </button>
          <button
            onClick={clearLog}
            style={{
              padding: '8px 16px',
              backgroundColor: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            🗑️ Clear Log
          </button>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Length</th>
            <th>Status</th>
            <th>Attack Type</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((pkt, i) => (
            <tr key={i} className={pkt.status === "Anomaly" ? "anomaly" : ""}>
              <td>{i + 1}</td>
              <td>{pkt.timestamp}</td>
              <td>{pkt.srcIp}</td>
              <td>{pkt.destIp}</td>
              <td>{pkt.protocol}</td>
              <td>{pkt.length}</td>
              <td>{pkt.status}</td>
              <td>{pkt.attackType || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default PacketsTable;