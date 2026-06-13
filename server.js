// server.js — minimal backend. Two jobs:
//   1. /api/claude  → forwards prompts to the Anthropic API, injecting the key
//      from the environment so it NEVER reaches the browser or the repo.
//   2. serves the built frontend (dist/) in production.
//
// Required env var:  ANTHROPIC_API_KEY
// Optional env vars:  CLAUDE_MODEL (default claude-opus-4-8), PORT, MAX_TOKENS

import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: "1mb" }));

const MODEL = process.env.CLAUDE_MODEL || "claude-opus-4-8";
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS || "4000", 10);
const PORT = process.env.PORT || 3001;

// expose the active model so the UI can display it accurately
app.get("/api/model", (_req, res) => res.json({ model: MODEL }));

app.post("/api/claude", async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return res.status(500).json({ error: "ANTHROPIC_API_KEY not set" });
  const { prompt, system } = req.body || {};
  if (!prompt) return res.status(400).json({ error: "prompt required" });

  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: MAX_TOKENS,
        system,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// serve the production build
app.use(express.static(path.join(__dirname, "dist")));
app.get("*", (_req, res) =>
  res.sendFile(path.join(__dirname, "dist", "index.html"))
);

app.listen(PORT, () => console.log(`triage-agent on :${PORT} (model ${MODEL})`));
