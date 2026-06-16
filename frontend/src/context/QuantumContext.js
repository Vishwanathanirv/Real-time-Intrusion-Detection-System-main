import React, { createContext, useEffect, useState } from "react";

export const QuantumContext = createContext();

export const QuantumProvider = ({ children }) => {
  const [quantum, setQuantum] = useState({
    enabled: false,
    mode: "Classical",
    features: [],
  });

  useEffect(() => {
    fetch("http://localhost:8080/api/system/status")
      .then(res => res.json())
      .then(data => {
        setQuantum({
          enabled: data.quantumEnabled,
          mode: data.mode,
          features: data.selectedFeatures || [],
        });
      })
      .catch(() => {
        setQuantum({
          enabled: false,
          mode: "Classical (Fallback)",
          features: [],
        });
      });
  }, []);

  return (
    <QuantumContext.Provider value={quantum}>
      {children}
    </QuantumContext.Provider>
  );
};
