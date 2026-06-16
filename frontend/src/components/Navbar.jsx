import React from "react";
import { Link, useLocation } from "react-router-dom";
import "./Navbar.css";

const Navbar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path ? "nav-link active" : "nav-link";

  return (
    <nav className="navbar-container">
      <div className="navbar-glass">
        <div className="logo-section">
          <div className="logo-icon">🛡️</div>
          <span className="logo-text">CHANAKYA <span className="highlight">SHIELD</span></span>
        </div>

        <ul className="nav-items">
          <li><Link to="/" className={isActive("/")}>Home</Link></li>
          <li><Link to="/dashboard" className={isActive("/dashboard")}>Dashboard</Link></li>
          <li><Link to="/packets" className={isActive("/packets")}>Live Traffic</Link></li>
          <li><Link to="/simulate" className={isActive("/simulate")}>Simulation</Link></li>
          <li><Link to="/alerts" className={isActive("/alerts")}>Alerts</Link></li>
        </ul>

        {/* Status Indicator (Purely cosmetic for 'connected' feel) */}
        <div className="system-status">
          <span className="status-dot"></span>
          <span className="status-text">SYSTEM ONLINE</span>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;