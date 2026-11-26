# PacketEye

Network intrusion detection. npm workspaces: `packages/core` (decoder, flow table, detectors, rules, isolation forest, simulator, recorder, what-if), `apps/api` (Fastify server, WebSocket, SQLite via `node:sqlite`, Telegram), `apps/web` (React 19 + Vite + Tailwind 4 dashboard). The Vercel demo (`build:demo`) compiles the sensor into a Web Worker (`apps/web/src/demo`), so no server is needed.

## Commands
- `npm run dev` (API :8080, web :5174) · `npm run build && npm start`
- `npm run lint && npm run typecheck && npm test` before every commit
- `npm run test:e2e` builds the demo and runs Playwright. On Windows run `node ../../scripts/copy-demo-assets.mjs && VITE_DEMO=1 npx vite build` from `apps/web` in Git Bash first; the npm script uses POSIX env syntax.
- `npm run evaluate` (simulated attacks) · `npm run benchmark` (NSL-KDD)

## Web layout
- `main.tsx` shell: top bar (status, live figures), tool nav, Overview (traffic, simulator, map, recent alerts, inspector), tool routes
- `map.tsx` network map: fixed columns (workstations, servers, internet), `place()` shared with the report
- `ui.tsx` alert row, alert body with triage, charts · `replay.tsx` Rewind · `pages/*` tools and the shared report

## Rules
- One dark theme. No italics. No intro modal, "How it works" page, "Try it" buttons or game metaphors (no radar, sonar or flight strips).
- Public Sans for text, Fira Code for figures and addresses. Blue = normal traffic, amber = medium or replay, red = attack.
- Packet contents are never read; detection uses shape, timing and handshakes.
- State-changing API routes are rate limited and protected by `ADMIN_TOKEN` when set.
- Measured numbers in the README come from `npm run evaluate` / `npm run benchmark`; never write numbers that were not measured.
- No personal details or repo links in code, UI or metadata.
