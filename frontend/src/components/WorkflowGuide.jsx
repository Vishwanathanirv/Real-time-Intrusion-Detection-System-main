import React, { useState } from "react";
import { Button, Card } from "@mui/material";
import { motion } from "framer-motion";
import "./WorkflowGuide.css";

const steps = [
  {
    title: "Step 1: Train ML Models 🧠",
    desc: "Train and save IsolationForest & RandomForest models using CICIDS2017 dataset.",
    command: "python mlmodel/train_model.py && python mlmodel/train_classifier.py",
  },
  {
    title: "Step 2: Start Spring Boot Backend ⚙️",
    desc: "Launch the backend server to expose API endpoints and connect with the database.",
    command: "mvn spring-boot:run",
  },
  {
    title: "Step 3: Capture Live Packets 🌐",
    desc: "Run the sniffer script to capture and classify network traffic in real time.",
    command: "python sniffer/sniffer.py",
  },
  {
    title: "Step 4: Simulate Attacks 💥 (Optional)",
    desc: "Use replay script to simulate known attacks from CICIDS dataset if no live traffic.",
    command: "python Testing/replay_from_csv.py",
  },
  {
    title: "Step 5: Telegram Alerts 📲",
    desc: "Run the Telegram alert service to receive live notifications for critical attacks.",
    command: "python Testing/telegram_alert_service_whitelist.py",
  },
  {
    title: "Step 6: Launch Dashboard 📊",
    desc: "Open the React dashboard to visualize network traffic, anomalies, and alerts.",
    command: "npm start",
  },
];

const WorkflowGuide = () => {
  const [active, setActive] = useState(null);

  return (
    <div className="workflow-container">
      <h1 className="workflow-title">🚀 PacketEye Pro — Interactive Workflow</h1>
      <p className="workflow-sub">Follow each step to launch your complete network threat analysis system.</p>

      <div className="workflow-grid">
        {steps.map((step, index) => (
          <motion.div
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.98 }}
            key={index}
          >
            <Card
              className={`workflow-card ${active === index ? "active" : ""}`}
              onClick={() => setActive(index)}
            >
              <h2>{step.title}</h2>
              <p>{step.desc}</p>
              {active === index && (
                <motion.div
                  className="workflow-command"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                >
                  <code>{step.command}</code>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={() => navigator.clipboard.writeText(step.command)}
                  >
                    Copy
                  </Button>
                </motion.div>
              )}
            </Card>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default WorkflowGuide;