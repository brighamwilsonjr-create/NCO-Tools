const express = require('express');
const cors = require('cors');
const path = require('path');
const PDFDocument = require('pdfkit');

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

// DA 4856 PDF Generation
app.post('/api/generate-4856', (req, res) => {
  const {
    soldierName, rank, date, unit, counselor, counselorRank,
    subject, situation, strengths, improve, poa, leader
  } = req.body;

  const doc = new PDFDocument({ margin: 40, size: 'letter' });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="DA4856_${(soldierName || 'counseling').replace(/[^a-z0-9]/gi, '_')}.pdf"`);
  doc.pipe(res);

  const W = 595 - 80; // usable width
  const L = 40;       // left margin
  const formattedDate = date ? new Date(date + 'T12:00:00').toLocaleDateString('en-US', { day: '2-digit', month: 'long', year: 'numeric' }) : '___________________';

  // Helper functions
  const box = (x, y, w, h) => doc.rect(x, y, w, h).stroke();
  const hline = (x, y, w) => doc.moveTo(x, y).lineTo(x + w, y).stroke();
  const label = (text, x, y, opts = {}) => {
    doc.fontSize(6.5).font('Helvetica').fillColor('#000').text(text, x, y, { ...opts, lineBreak: false });
  };
  const field = (text, x, y, w, opts = {}) => {
    doc.fontSize(9).font('Helvetica').fillColor('#000').text(text || '', x, y, { width: w, ...opts });
  };
  const sectionHeader = (text, x, y, w) => {
    doc.rect(x, y, w, 14).fillAndStroke('#000', '#000');
    doc.fontSize(8).font('Helvetica-Bold').fillColor('#fff').text(text, x + 4, y + 3, { lineBreak: false });
    doc.fillColor('#000');
  };

  let y = 40;

  // ── FORM TITLE ──
  doc.fontSize(10).font('Helvetica-Bold').text('DEVELOPMENTAL COUNSELING FORM', L, y, { align: 'center', width: W });
  y += 14;
  doc.fontSize(7).font('Helvetica').text('For use of this form, see FM 6-22; the proponent agency is TRADOC', L, y, { align: 'center', width: W });
  y += 6;
  doc.fontSize(7).font('Helvetica').text('DATA REQUIRED BY THE PRIVACY ACT OF 1974', L, y, { align: 'center', width: W });
  y += 10;

  // ── PART I HEADER ──
  sectionHeader('PART I - ADMINISTRATIVE DATA', L, y, W);
  y += 16;

  // Row 1: Name | Rank | Date
  box(L, y, W * 0.45, 28);
  box(L + W * 0.45, y, W * 0.25, 28);
  box(L + W * 0.70, y, W * 0.30, 28);
  label('Name (Last, First, MI)', L + 3, y + 2);
  label('Rank/Grade', L + W * 0.45 + 3, y + 2);
  label('Date of Counseling', L + W * 0.70 + 3, y + 2);
  field(soldierName || '', L + 3, y + 12, W * 0.45 - 6);
  field(rank || '', L + W * 0.45 + 3, y + 12, W * 0.25 - 6);
  field(formattedDate, L + W * 0.70 + 3, y + 12, W * 0.30 - 6);
  y += 28;

  // Row 2: Organization | Counselor Name | Counselor Rank
  box(L, y, W * 0.45, 28);
  box(L + W * 0.45, y, W * 0.30, 28);
  box(L + W * 0.75, y, W * 0.25, 28);
  label('Organization', L + 3, y + 2);
  label('Name and Title of Counselor', L + W * 0.45 + 3, y + 2);
  label('Counselor Rank', L + W * 0.75 + 3, y + 2);
  field(unit || '', L + 3, y + 12, W * 0.45 - 6);
  field(counselor || '', L + W * 0.45 + 3, y + 12, W * 0.30 - 6);
  field(counselorRank || '', L + W * 0.75 + 3, y + 12, W * 0.25 - 6);
  y += 28;

  // ── PART II HEADER ──
  sectionHeader('PART II - BACKGROUND INFORMATION', L, y, W);
  y += 16;

  // Purpose / Subject
  box(L, y, W, 24);
  label('Purpose of Counseling (Reason for counseling; include what precipitated this counseling, i.e., performance/professional or personal)', L + 3, y + 2, { width: W - 6 });
  field(subject || '', L + 3, y + 13, W - 6);
  y += 24;

  // Situation block
  const sitLines = Math.max(4, Math.ceil((situation || '').length / 90));
  const sitH = Math.min(Math.max(sitLines * 13, 60), 130);
  box(L, y, W, sitH);
  label('Key Facts / Background', L + 3, y + 2);
  doc.fontSize(8.5).font('Helvetica').text(situation || '', L + 3, y + 13, { width: W - 6, height: sitH - 16 });
  y += sitH;

  // ── PART III HEADER ──
  sectionHeader('PART III - SUMMARY OF COUNSELING', L, y, W);
  y += 16;
  label('Complete this section during or immediately subsequent to counseling', L + 3, y);
  y += 12;

  // Strengths
  if (strengths) {
    const strH = Math.min(Math.max(Math.ceil(strengths.length / 90) * 13, 45), 100);
    box(L, y, W, strH);
    label('STRENGTHS / COMMENDABLE PERFORMANCE', L + 3, y + 2);
    doc.fontSize(8.5).font('Helvetica').text(strengths, L + 3, y + 13, { width: W - 6, height: strH - 16 });
    y += strH;
  }

  // Improvement
  if (improve) {
    const impH = Math.min(Math.max(Math.ceil(improve.length / 90) * 13, 45), 100);
    box(L, y, W, impH);
    label('AREAS REQUIRING IMPROVEMENT', L + 3, y + 2);
    doc.fontSize(8.5).font('Helvetica').text(improve, L + 3, y + 13, { width: W - 6, height: impH - 16 });
    y += impH;
  }

  // Plan of Action
  const poaH = Math.min(Math.max(Math.ceil((poa || '').length / 90) * 13, 60), 120);
  box(L, y, W, poaH);
  label('Plan of Action (Identifies actions that the subordinate will do after the counseling session to reach the agreed upon goal(s))', L + 3, y + 2, { width: W - 6 });
  doc.fontSize(8.5).font('Helvetica').text(poa || '', L + 3, y + 13, { width: W - 6, height: poaH - 16 });
  y += poaH;

  // Leader responsibilities
  const ldrH = Math.min(Math.max(Math.ceil((leader || '').length / 90) * 13, 50), 100);
  box(L, y, W, ldrH);
  label('Leader Responsibilities (Specify actions that the leader will do to assist the subordinate in reaching the agreed upon goal(s))', L + 3, y + 2, { width: W - 6 });
  doc.fontSize(8.5).font('Helvetica').text(leader || '', L + 3, y + 13, { width: W - 6, height: ldrH - 16 });
  y += ldrH;

  // ── PART IV HEADER ──
  if (y > 680) { doc.addPage(); y = 40; }
  sectionHeader('PART IV - ASSESSMENT OF THE PLAN OF ACTION', L, y, W);
  y += 16;

  box(L, y, W, 50);
  label('Assessment (Did the plan of action achieve the desired results? This section is completed by both the leader and the subordinate.)', L + 3, y + 2, { width: W - 6 });
  label('The plan of action:  [ ] Was Accomplished    [ ] Was Not Accomplished', L + 3, y + 16);
  label('Follow-up counseling required:  [ ] Yes    [ ] No', L + 3, y + 28);
  label('Date of Follow-up Counseling: ______________________', L + 3, y + 40);
  y += 50;

  // ── SIGNATURES ──
  sectionHeader('SIGNATURES', L, y, W);
  y += 16;

  // Individual counseled
  box(L, y, W, 45);
  label('INDIVIDUAL COUNSELED', L + 3, y + 2);
  label('I agree / disagree with the information above.', L + 3, y + 13);
  label('Signature: _______________________________________', L + 3, y + 25);
  label('Date: ____________________', L + W * 0.6, y + 25);
  label('Comments: _____________________________________________', L + 3, y + 36);
  y += 45;

  // Leader/Counselor
  box(L, y, W, 40);
  label('LEADER / COUNSELOR', L + 3, y + 2);
  label(`Signature: _______________________________________`, L + 3, y + 14);
  label('Date: ____________________', L + W * 0.6, y + 14);
  label(`${counselorRank || ''} ${counselor || ''}`, L + 3, y + 28);
  y += 40;

  // Footer note
  y += 6;
  doc.fontSize(6.5).font('Helvetica-Oblique').fillColor('#333')
    .text('NOTE: The counselee\'s signature confirms that this counseling has taken place and is NOT agreement with the content herein. Retain original; provide copy to individual counseled.', L, y, { width: W });
  y += 14;
  doc.fontSize(6.5).font('Helvetica').fillColor('#666')
    .text(`DA FORM 4856  |  Generated by NCO Tools  |  Review all content before official use`, L, y, { width: W, align: 'center' });

  doc.end();
});

// AI Counseling Enhancement endpoint
app.post('/api/enhance-counseling', async (req, res) => {
  const { rawText, section, soldierName, rank, counselingType } = req.body;

  if (!rawText) return res.status(400).json({ error: 'Text is required.' });

  const sectionContext = {
    situation: 'the Background Information / Purpose of Counseling section — describe what occurred factually and professionally',
    strengths: 'the Strengths and Commendable Performance section — highlight positive attributes and accomplishments professionally',
    improvement: 'the Areas Requiring Improvement section — describe deficiencies professionally without personal attacks',
    plan_of_action: 'the Plan of Action section — specific, measurable, achievable actions the soldier will take with clear timelines',
    leader_responsibilities: 'the Leader Responsibilities section — what the counselor commits to doing to support the soldier'
  };

  const prompt = `You are an expert Army NCO writer who specializes in DA Form 4856 Developmental Counseling Forms. You write in precise, professional Army regulatory language following AR 623-3 and FM 6-22 standards.

Rewrite the following rough notes into polished, professional Army language suitable for ${sectionContext[section] || 'a DA 4856 counseling form'}.

Soldier: ${rank} ${soldierName}
Counseling Type: ${counselingType}
Raw Notes: ${rawText}

Rules:
- Write in third person (refer to soldier by rank and last name)
- Use professional, regulatory Army language
- Be specific and factual — no vague language
- Do not add information that wasn't in the original notes
- Keep it concise but complete
- Do not use bullet points — write in paragraph form
- Do not include section headers or labels in your response
- Output ONLY the rewritten text, nothing else`;

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
        max_tokens: 500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });

    const enhanced = data.content.map(i => i.text || '').join('').trim();
    res.json({ enhanced });

  } catch (err) {
    console.error('Counseling enhance error:', err);
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
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
