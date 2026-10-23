# ScamShield AI
# ScamShield AI

🌐 **Live Website:** [Visit ScamShield AI](https://scam-shield-ai-sandy.vercel.app/?utm_source=chatgpt.com)

A full-stack scam-awareness and risk-screening application built with React, Vite, CSS and Express.
## Features
- Message and URL risk screening with explainable warning signs.
- Fake job offer checker (recruiter, company, salary, fees, interview and contact details).
- Risk levels: Low, Medium, High.
- Interactive examples and a scored safety quiz.
- Recent scan history stored in the browser.
- Express REST API.
- Optional Google Safe Browsing URL lookup (server-side API key).

> ScamShield is an educational screening aid, not an authoritative verification service. A low-risk result does not prove that a message, job, company or URL is legitimate. Always verify through independently located official channels. Never submit passwords, OTPs, full card details, or private identity documents.

## Requirements
- Node.js 18+ and npm

## Run locally
Open a terminal in this folder:

```bash
npm install
npm run install:all
npm run dev
```

Open the Vite URL shown in the terminal (normally http://localhost:5173). The API runs on http://localhost:5000.

## Optional Google Safe Browsing
1. Create `server/.env` based on `server/.env.example`.
2. Add your Google Safe Browsing API key.
3. Restart the server.

The API key stays on the server and is never sent to the React client. URL lookup is optional; heuristic screening still works without it. Review Google's current terms, quotas and eligibility before production use.

## API endpoints
- `GET /api/health`
- `POST /api/analyze/message` body: `{ "message": "..." }`
- `POST /api/analyze/job` body: `{ "company": "...", "role": "...", "salary": "...", "applicationFee": "...", "recruiterEmail": "...", "jobDescription": "..." }`
- `POST /api/threat-check` body: `{ "url": "https://example.com" }`
- `GET /api/examples`
- `GET /api/quiz`

## Production notes
- Add rate limiting, request logging with sensitive-data redaction, monitoring and HTTPS before public deployment.
- Do not store submitted message contents or personal data without explicit consent and a retention policy.
- Replace demo heuristics with a reviewed detection pipeline and verified threat-intelligence providers.
- Configure CORS for your deployed frontend domain instead of allowing all origins.
- Add legal/privacy pages and accessibility/security testing before launch.
