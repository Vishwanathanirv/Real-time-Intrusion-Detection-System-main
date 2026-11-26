# PacketEye · Spec

## Problem
Intrusion detection produces thousands of log lines; the one that matters is hard to find and harder to read. Sensors and dashboards are separate tools.

## Core (MVP)
One sensor that detects attacks from traffic shape, explains each alert with evidence and next steps, and lets you replay it.

## Flow
1. Overview: live figures, traffic chart, network map, recent alerts, inspector (network summary by default)
2. Select an alert or host → inspector shows evidence, MITRE ATT&CK, next steps, triage
3. Replay this incident → Rewind plays the map back; Back to live
4. Share report → a self-contained link (`/report#…`)
5. Tools: Alerts, What-if lab, TLS clients, Rules, Analyse a pcap, Coverage
6. Sources: simulator (default), live interface (`CAPTURE_INTERFACE`), uploaded pcap

## Data
| Store | Holds |
| --- | --- |
| SQLite `alerts` | id, type, severity, title, description, src, dst, first_seen, last_seen, count, mitre (JSON), evidence (JSON), status (open, acknowledged, resolved), note, source |
| Recorder (memory) | one frame a second for five minutes: graph, packets, bytes |
| Browser localStorage | `packeteye-plain` (explain mode), `packeteye-sound` (alert sound) |
| Report link | alert plus frames, compressed into the URL fragment |

The demo runs the same sensor in a Web Worker; alerts live in memory for the session.

## API limits
| Route | Limit |
| --- | --- |
| all routes | 600/min per client |
| POST /api/attacks | 20/min, `ADMIN_TOKEN` when set |
| POST /api/pcap | 6/min, 55 MB body |
| PUT /api/live, /api/config, /api/rules | `ADMIN_TOKEN` when set |

## States
- Loading: "Connecting" status, skeleton traffic chart, "Waiting for traffic…" on the map, skeletons for tools and the report.
- Empty: no alerts → prompt to launch an attack from the simulator; during replay → "No alerts had been raised at this moment"; empty alert filter → "No open alerts."
- Errors: broken report link → "No report here"; invalid rules → line numbers; failed API calls → message under the simulator; replay disabled for alerts older than the recorder window.

## Out of scope
Reading payloads, active blocking, multi-sensor fleets.
