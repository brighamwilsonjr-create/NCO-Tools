const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (req, res) => res.json({ status: 'online' }));
app.get('/test-key', async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return res.json({ error: 'No API key found in environment' });
  res.json({ key_present: true, starts_with: key.substring(0, 12) + '...' });
});
// AI Bullet Generation endpoint
app.post('/api/bullets', async (req, res) => {
  const { name, category, action, impact, count } = req.body;

  if (!action) {
    return res.status(400).json({ error: 'Action field is required.' });
  }

  const prompt = `You are an expert Army NCO who writes exceptional NCOER evaluation bullets. Your bullets are concise, action-oriented, and follow Army writing standards.

Generate exactly ${count || 3} NCOER bullet(s) for the "${category}" section of an NCOER.

Soldier: ${name || 'Soldier'}
What they did: ${action}
${impact ? `Metrics/Impact: ${impact}` : ''}

Rules for Army NCOER bullets:
- Start with a strong action verb (Led, Trained, Managed, Executed, Coordinated, Achieved, etc.)
- Be specific and measurable where possible
- Use third person — never use "I"
- Each bullet should be one sentence, punchy and direct
- Do NOT use the soldier's name in the bullet (use their rank if needed, e.g. "SGT")
- Format: action verb + what + result/impact
- Keep each bullet under 175 characters
- Do NOT number the bullets or add bullet symbols

Respond with ONLY the bullets, one per line, nothing else. No preamble, no explanation.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();

    if (data.error) {
      return res.status(500).json({ error: data.error.message });
    }

    const text = data.content.map(i => i.text || '').join('').trim();
    const bullets = text.split('\n').map(b => b.trim()).filter(b => b.length > 0);

    res.json({ bullets });

  } catch (err) {
    console.error('API error:', err);
    res.status(500).json({ error: 'Failed to reach AI service. Try again.' });
  }
});

// Serve the app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NCO Tools running on port ${PORT}`));
