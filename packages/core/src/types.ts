export type Proto = "tcp" | "udp" | "icmp";

export const TCP = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 } as const;

/** A decoded IPv4 packet, reduced to what detection needs. */
export type Packet = {
  ts: number; // epoch ms (fractional)
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: Proto;
  len: number; // bytes on the wire
  flags: number; // TCP flags, 0 otherwise
  ttl: number;
  dnsQuery?: string;
  payloadLen: number;
};

export type Flow = {
  id: string;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: Proto;
  start: number;
  last: number;
  packets: number;
  bytes: number;
  fwdPackets: number;
  bwdPackets: number;
  fwdBytes: number;
  bwdBytes: number;
  syn: number;
  synAck: number;
  ack: number;
  rst: number;
  fin: number;
  /** True once the three-way handshake completed. */
  established: boolean;
};

export type Severity = "low" | "medium" | "high" | "critical";

export type Mitre = { id: string; name: string; tactic: string };

export type AlertType = "port_scan" | "host_sweep" | "syn_flood" | "brute_force" | "dns_tunnel" | "beaconing" | "anomaly";

export type Alert = {
  id: string;
  type: AlertType;
  severity: Severity;
  title: string;
  description: string;
  src: string;
  dst: string;
  firstSeen: number;
  lastSeen: number;
  count: number;
  mitre: Mitre;
  evidence: Record<string, number | string>;
};

export const MITRE: Record<AlertType, Mitre> = {
  port_scan: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  host_sweep: { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
  syn_flood: { id: "T1498.001", name: "Network Denial of Service: Direct Network Flood", tactic: "Impact" },
  brute_force: { id: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access" },
  dns_tunnel: { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "Command and Control" },
  beaconing: { id: "T1071.001", name: "Application Layer Protocol: Web Protocols (beaconing)", tactic: "Command and Control" },
  anomaly: { id: "TA0011", name: "Unusual flow (unsupervised)", tactic: "Command and Control / Exfiltration" },
};
