// Vercel serverless entry: POST /agent
import { handleAgentRequest } from "../src/handler.js";

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "method not allowed" });
    return;
  }
  // Same 1MB cap as the local dev server: reject oversize bodies before
  // reading them fully (no legitimate envelope is anywhere near this).
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      res.status(413).json({ error: "payload too large" });
      return;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const out = await handleAgentRequest(raw, req.headers);
  res.status(out.status);
  for (const [k, v] of Object.entries(out.headers || {})) res.setHeader(k, v);
  res.send(out.body);
}
