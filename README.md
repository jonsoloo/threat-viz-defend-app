# Threat Viz Defend frontend

Static HTML/CSS/JavaScript website for scanning code samples and visualizing potential threat paths. The homepage code and threat diagram are an illustration. Preview with VS Code Live Server or run `python3 -m http.server 8000` in this folder and visit `http://localhost:8000`. Account creation and the shared access gate are implemented in `../backend/`; code analysis and updated diagrams still require the team's analyzer. No password or shared access code is stored in these files. The account forms need the backend online and cannot work with Live Server alone.

## Backend contract

Leave `window.THREAT_VIZ_API_BASE` empty in `config.js` when the backend service is mounted under `/api` on the same DigitalOcean app. Calls send JSON with `credentials: include`.

| Method and path | Request JSON | Successful JSON / behavior |
| --- | --- | --- |
| GET `/api/session` | — | `{ "authenticated": false, "approved": false }` or `{ "authenticated": true, "approved": true/false }` |
| POST `/api/auth/signup` | `{ "username": "...", "password": "..." }` | Creates account and session, or requires login afterward |
| POST `/api/auth/login` | `{ "username": "...", "password": "..." }` | Creates authenticated session |
| POST `/api/access/redeem` | `{ "code": "..." }` | Validates shared code server-side, marks current account approved |
| POST `/api/auth/logout` | `{}` | Clears session |
| POST `/api/analyze` | `{ "code": "required source code" }` | `{ "summary": "...", "findings": [{ "title": "...", "severity": "high", "description": "...", "mitigation": "..." }], "diagram": { "nodes": [{ "id": "input", "label": "User input", "kind": "source" }, { "id": "sink", "label": "Shell command", "kind": "risk" }], "edges": [{ "from": "input", "to": "sink", "label": "Untrusted input reaches a command" }] }, "runId": "opaque-id", "status": "watching" }` |
| GET `/api/runs/{runId}/state` | — | Latest snapshot in the same format: `diagram`, `findings`, `summary`, `status`. Return a new snapshot when a new code analysis is available. |

The analyze response must include a complete `diagram` snapshot (`nodes` and `edges`). `runId` is optional: a standalone scan can return a completed diagram without one. If the backend continues checking code changes, it can generate a new diagram and findings snapshot and expose it through the state endpoint. While the backend reports `status: "watching"` or `"running"`, the frontend polls every three seconds while the workspace is open; `"complete"` or `"failed"` stops polling. Each response should return the entire current diagram, not a partial change. Node IDs must be unique; edges refer to those IDs. Set `kind: "risk"` on risk nodes to highlight them. The frontend shows up to 20 nodes, 40 edges, and 30 findings. Avoid returning secrets or private code in diagram labels and findings.

Return `{ "error": "Short explanation" }` for errors. Use 401 for signed-out requests, 403 for signed-in accounts lacking access, and 429 for rate limits. The backend must check the session and approved status on **every** protected endpoint, especially `/api/analyze` and `/api/runs/{runId}/state`; the frontend screen is only a convenience. Scope each run ID to its owner. Keep the shared access code in backend configuration, not in frontend code or Git. Hash passwords on the server and limit signup, login, code verification, and AI analysis requests.

Keep the frontend and API on the same site origin using DigitalOcean App Platform routes `/` and `/api`. Set `SITE_ORIGIN` to the canonical HTTPS URL of the frontend on the API service. See `../backend/README.md` for the working account service and security controls.

## Deployment

Deploy `frontend/` as a static site at `/` and `backend/` as a web service at `/api` in the same DigitalOcean app. Attach PostgreSQL and configure the backend environment variables as documented in `../backend/README.md`. Test signup, login, code redemption, logout, and rejected unauthorized requests before sharing the code. Real scans and diagram updates depend on the team's analyzer being connected behind the gated API.
