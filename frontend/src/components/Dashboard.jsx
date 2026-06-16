import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { saveAs } from 'file-saver';

function Dashboard() {
  const [packets, setPackets] = useState([]);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('All');

  useEffect(() => {
    const fetchPackets = () => {
      axios.get('http://localhost:8080/api/packets')
        .then(res => setPackets(res.data))
        .catch(err => console.error('Failed to fetch packets:', err));
    };

    fetchPackets();
    const interval = setInterval(fetchPackets, 5000); 
    return () => clearInterval(interval); 
  }, []);

  
  const filteredPackets = filter === 'All'
    ? packets
    : packets.filter(p => p.protocol === filter);

  const displayedPackets = filteredPackets.filter(p =>
    p.srcIp.includes(search) || p.destIp.includes(search)
  );


  const downloadCSV = () => {
    const headers = ['ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length'];
    const rows = packets.map(p => [p.id, p.timestamp, p.srcIp, p.destIp, p.protocol, p.length]);
    const csvContent = [headers, ...rows].map(e => e.join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    saveAs(blob, 'captured_packets.csv');
  };

  const clearLog = () => {
    if (window.confirm('Are you sure you want to clear all packet logs? This action cannot be undone.')) {
      axios.delete('http://localhost:8080/api/packets')
        .then(res => {
          alert(res.data.message || 'Packets cleared successfully!');
          setPackets([]);
        })
        .catch(err => {
          console.error('Failed to clear packets:', err);
          alert('Failed to clear packets. Please try again.');
        });
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      <h2>Captured Packets</h2>

      {/* Controls */}
      <div style={{ marginBottom: '10px' }}>
        <input
          type="text"
          placeholder="Search by IP"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ padding: '6px', marginRight: '10px' }}
        />

        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ padding: '6px', marginRight: '10px' }}
        >
          <option value="All">All Protocols</option>
          <option value="6">TCP (6)</option>
          <option value="17">UDP (17)</option>
          <option value="1">ICMP (1)</option>
        </select>

        <button onClick={downloadCSV} style={{ padding: '6px', marginRight: '10px' }}>
          Download CSV
        </button>

        <button 
          onClick={clearLog} 
          style={{ 
            padding: '6px', 
            backgroundColor: '#dc3545', 
            color: 'white', 
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          🗑️ Clear Log
        </button>
      </div>

      {displayedPackets.length === 0 ? (
        <p>No packets found.</p>
      ) : (
        <table border="1" cellPadding="8" style={{ borderCollapse: 'collapse', width: '100%' }}>
          <thead>
            <tr>
              <th>#</th>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Protocol</th>
              <th>Length</th>
            </tr>
          </thead>
          <tbody>
            {displayedPackets.map((p, i) => (
              <tr
                key={p.id}
                style={{ backgroundColor: p.length > 200 ? '#ffe0e0' : 'white' }}
              >
                <td>{i + 1}</td>
                <td>{p.timestamp}</td>
                <td>{p.srcIp}</td>
                <td>{p.destIp}</td>
                <td>{p.protocol}</td>
                <td>{p.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default Dashboard;