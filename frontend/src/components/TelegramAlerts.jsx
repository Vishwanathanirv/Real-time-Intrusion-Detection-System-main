import React, { useState, useEffect } from "react";
import "./TelegramAlerts.css";

const TelegramAlerts = () => {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await fetch("http://localhost:8080/api/packets?status=Anomaly");
        const data = await res.json();
        setAlerts(data.slice(0, 15));
      } catch (err) {
        console.error("Error fetching alerts:", err);
      }
    };
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="alerts-container">
      <h2>📲 Live Telegram Alerts</h2>
      <ul>
        {alerts.map((alert, i) => (
          <li key={i} className="alert-item">
            <strong>{alert.attackType}</strong> — {alert.srcIp} → {alert.destIp} ({alert.timestamp})
          </li>
        ))}
      </ul>
    </div>
  );
};

export default TelegramAlerts;