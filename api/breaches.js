export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const email = String(req.query.email || "").trim();
  if (!email || !email.includes("@")) return res.status(400).json({ error: "Укажи корректный email." });

  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) return res.status(503).json({ error: "HIBP API key не настроен.", setup: "Добавь HIBP_API_KEY в Vercel Environment Variables." });

  try {
    const response = await fetch("https://haveibeenpwned.com/api/v3/breachedaccount/" + encodeURIComponent(email), {
      headers: { "hibp-api-key": apiKey, "user-agent": "OSINT-Hub/1.0" }
    });
    const text = await response.text();
    if (response.status === 404) return res.status(404).json({ email, breaches: [], message: "Email не найден в доступных записях Have I Been Pwned." });

    let data;
    try { data = JSON.parse(text); } catch { data = { message: text || "HIBP вернул неожиданный ответ." }; }
    if (!response.ok) return res.status(response.status).json({ error: data.message || "HIBP API error", status: response.status });
    return res.status(200).json(data);
  } catch (error) {
    return res.status(502).json({ error: "Не удалось связаться с Have I Been Pwned.", details: error.message });
  }
}