
import React, { useEffect, useState } from 'react';
import axios from 'axios';

const PacketList = () => {
  const [packets, setPackets] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:8080/api/packets")
      .then(response => {
        setPackets(response.data);
      })
      .catch(error => {
        console.error("Error fetching packets:", error);
      });
  }, []);

  return (
    <div style={{ padding: '20px' }}>
      <h2>Captured Packets</h2>
      <table border="1" cellPadding="8">
        <thead>
          <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Length</th>
          </tr>
        </thead>
        <tbody>
          {packets.map(packet => (
            <tr key={packet.id}>
              <td>{packet.id}</td>
              <td>{packet.timestamp}</td>
              <td>{packet.srcIp}</td>
              <td>{packet.destIp}</td>
              <td>{packet.protocol}</td>
              <td>{packet.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default PacketList;
