import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import { analyzeMessage, analyzeJob } from "./analyzer.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:5173" }));
app.use(express.json({ limit: "30kb" }));

app.get("/api/health", (_req, res) => res.json({ status: "ok", service: "ScamShield AI API" }));
app.post("/api/analyze/message", (req, res, next) => {
  try { res.json(analyzeMessage(req.body?.message)); } catch (e) { next(e); }
});
app.post("/api/analyze/job", (req, res, next) => {
  try { res.json(analyzeJob(req.body || {})); } catch (e) { next(e); }
});
app.post("/api/threat-check", async (req, res) => {
  const url = String(req.body?.url || "").trim();
  let parsed;
  try { parsed = new URL(url); } catch { return res.status(400).json({ error: "Enter a valid URL including https:// or http://." }); }
  if (!["http:", "https:"].includes(parsed.protocol)) return res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported." });
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!key) return res.json({ available: false, checked: false, message: "Threat-intelligence lookup is not configured. Local message screening remains available." });
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "scamshield-ai", clientVersion: "1.0.0" },
        threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }] }
      })
    });
    if (!response.ok) return res.status(502).json({ available: true, checked: false, message: "Threat-intelligence provider could not complete the lookup." });
    const data = await response.json();
    const unsafe = Boolean(data.matches?.length);
    res.json({ available: true, checked: true, unsafe, level: unsafe ? "High Risk" : "No known match found", message: unsafe ? "The provider reported a known threat match. Do not visit this URL." : "No match was returned. This does not guarantee the URL is safe." });
  } catch { res.status(502).json({ available: true, checked: false, message: "Threat-intelligence lookup failed. Try again later." }); }
});
app.get("/api/examples", (_req, res) => res.json([
  { title: "Fake bank KYC alert", type: "Phishing", message: "URGENT: Your bank account will be blocked today. Click here to update KYC and verify your OTP immediately.", lesson: "Banks do not need your OTP by message. Open your bank's official app or call the number on your card." },
  { title: "Work-from-home fee scam", type: "Fake job", message: "Congratulations! Earn ₹8,000 daily from home. Pay a refundable registration fee today. No interview required.", lesson: "Do not pay to get a job. Verify the vacancy on the employer's official careers website." },
  { title: "Prize claim scam", type: "Prize fraud", message: "You have won a prize! Pay a small processing charge to claim your reward. Click this link now.", lesson: "Unexpected prizes that require payment are a common fraud pattern." }
]));
app.get("/api/quiz", (_req, res) => res.json([
  { question: "A recruiter asks you to pay a refundable registration fee before an interview. What should you do?", options: ["Pay quickly", "Verify independently and do not pay", "Send your OTP"], answer: 1, explanation: "Upfront recruitment fees are a major warning sign. Verify the vacancy through the company's official channel." },
  { question: "You receive a bank message asking for your OTP through a link. What is safest?", options: ["Enter the OTP", "Forward it to the sender", "Do not share it; contact the bank through its official app/number"], answer: 2, explanation: "Never share OTPs. Contact the bank using a channel you locate independently." },
  { question: "A job offer promises very high pay with no interview and no clear job description. What does this mean?", options: ["Definitely genuine", "It has warning signs and needs verification", "Guaranteed employment"], answer: 1, explanation: "Unrealistic promises and vague hiring details should be independently checked." },
  { question: "Does an HTTPS padlock prove a website is legitimate?", options: ["Yes, always", "No, it only indicates an encrypted connection", "Only on phones"], answer: 1, explanation: "Scam websites can also use HTTPS. Check the exact domain and source." }
]));
app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message || "Unexpected server error." }));
app.listen(PORT, () => console.log(`ScamShield API running at http://localhost:${PORT}`));
