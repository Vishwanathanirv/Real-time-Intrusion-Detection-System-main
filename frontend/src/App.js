import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./components/Home";
import PacketsTable from "./components/PacketsTable";
import PacketEyeDashboard from "./components/PacketEyePro_Dashboard";
import SimulateAttack from "./components/SimulateAttack";
import TelegramAlerts from "./components/TelegramAlerts";
import "./App.css";

function App() {
  return (
    <Router>
      <div className="App">
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/packets" element={<PacketsTable />} />
          <Route path="/dashboard" element={<PacketEyeDashboard />} />
          <Route path="/simulate" element={<SimulateAttack />} />
          <Route path="/alerts" element={<TelegramAlerts />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;