// Vercel serverless entry: GET /health
// Keep this response in sync with src/server.js (production runs the
// bundled server.js, this entry mirrors it). kurierSubmitEnabled is
// computed inline here to avoid pulling snarkjs into the health
// function; it must match kurierSubmitEnabled() in src/proof.js:
// KURIER_SUBMIT=true AND a key present.
export default async function handler(req, res) {
  res.status(200).json({
    ok: true,
    service: "warden-agentgames",
    version: "0.1.1",
    time: new Date().toISOString(),
    kurierConfigured: Boolean(process.env.KURIER_API_KEY),
    kurierSubmitEnabled: process.env.KURIER_SUBMIT === "true" && Boolean(process.env.KURIER_API_KEY),
    secretConfigured: Boolean(process.env.AGENT_SECRET || process.env.AGENT_GAMES_HMAC_SECRET),
    // Boolean only, never the value: the deployed endpoint can only
    // generate vfy-policy proofs when the registered salt is set.
    vfySaltConfigured: Boolean(process.env.AGENT_GAMES_VFY_SALT),
  });
}
