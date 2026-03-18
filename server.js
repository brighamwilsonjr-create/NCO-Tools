const express = require('express');
const cors = require('cors');
const path = require('path');
const { calculateAFT } = require('./aft_tables');


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

// AFT Score Calculation
app.post('/api/aft-score', (req, res) => {
  try {
    const result = calculateAFT(req.body);
    res.json(result);
  } catch (err) {
    console.error('AFT score error:', err);
    res.status(500).json({ error: 'Score calculation failed: ' + err.message });
  }
});

// DA 705 PDF Generation
app.post('/api/generate-705', (req, res) => {
  try {
    const { name, sex, unit, mos, payGrade, age, standard, date,
            mdl, hrp, sdc, plk, tmr, oicName, scores, total, overallPass } = req.body;

    const doc = new PDFDocument({ margin: 36, size: 'letter' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="DA705_${(name||'AFT').replace(/[^a-z0-9]/gi,'_')}.pdf"`);
    doc.pipe(res);

    const W = 595 - 72;
    const L = 36;
    let y = 36;

    const box = (x, y, w, h) => doc.rect(x, y, w, h).stroke();
    const fillBox = (x, y, w, h, color) => doc.rect(x, y, w, h).fill(color).stroke('#000');
    const lbl = (text, x, y, opts={}) => doc.fontSize(6).font('Helvetica').fillColor('#000').text(text, x, y, { lineBreak: false, ...opts });
    const val = (text, x, y, w, opts={}) => doc.fontSize(9).font('Helvetica-Bold').fillColor('#000').text(text||'', x, y, { width: w, lineBreak: false, ...opts });
    const hdr = (text, x, y, w) => {
      doc.rect(x, y, w, 13).fill('#000');
      doc.fontSize(7).font('Helvetica-Bold').fillColor('#fff').text(text, x+2, y+3, { lineBreak: false });
      doc.fillColor('#000');
    };

    // Title
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#000')
      .text('ARMY FITNESS TEST SCORECARD', L, y, { align: 'center', width: W });
    y += 13;
    doc.fontSize(6).font('Helvetica')
      .text('DA FORM 705  |  For use of this form, see ATP 7-22.01; proponent agency is TRADOC', L, y, { align: 'center', width: W });
    y += 10;

    // Header info row
    box(L, y, W*0.4, 22);
    box(L+W*0.4, y, W*0.15, 22);
    box(L+W*0.55, y, W*0.15, 22);
    box(L+W*0.70, y, W*0.15, 22);
    box(L+W*0.85, y, W*0.15, 22);
    lbl('NAME (Last, First, MI)', L+2, y+2);
    lbl('SEX', L+W*0.4+2, y+2);
    lbl('DATE (YYYYMMDD)', L+W*0.55+2, y+2);
    lbl('STANDARD', L+W*0.70+2, y+2);
    lbl('PAY GRADE', L+W*0.85+2, y+2);
    val(name||'', L+2, y+11, W*0.4-4);
    val(sex||'', L+W*0.4+2, y+11, W*0.15-4);
    val(date||'', L+W*0.55+2, y+11, W*0.15-4);
    val((standard||'').toUpperCase(), L+W*0.70+2, y+11, W*0.15-4);
    val(payGrade||'', L+W*0.85+2, y+11, W*0.15-4);
    y += 22;

    // Unit / MOS / Age row
    box(L, y, W*0.5, 20);
    box(L+W*0.5, y, W*0.25, 20);
    box(L+W*0.75, y, W*0.25, 20);
    lbl('UNIT/LOCATION', L+2, y+2);
    lbl('MOS', L+W*0.5+2, y+2);
    lbl('AGE', L+W*0.75+2, y+2);
    val(unit||'', L+2, y+10, W*0.5-4);
    val(mos||'', L+W*0.5+2, y+10, W*0.25-4);
    val(age||'', L+W*0.75+2, y+10, W*0.25-4);
    y += 20;

    // EVENTS SECTION
    hdr('TEST ONE — EVENT SCORES', L, y, W);
    y += 15;

    const events = [
      { label: '3-REP MAX DEADLIFT (MDL)', unit: 'lbs', raw: mdl, pts: scores?.mdl },
      { label: 'HAND-RELEASE PUSH-UP (HRP)', unit: 'reps', raw: hrp, pts: scores?.hrp },
      { label: 'SPRINT-DRAG-CARRY (SDC)', unit: 'M:SS', raw: sdc, pts: scores?.sdc },
      { label: 'PLANK (PLK)', unit: 'M:SS', raw: plk, pts: scores?.plk },
      { label: 'TWO-MILE RUN (2MR)', unit: 'MM:SS', raw: tmr, pts: scores?.tmr },
    ];

    events.forEach(ev => {
      const pass = ev.pts >= 60;
      box(L, y, W*0.40, 18);
      box(L+W*0.40, y, W*0.15, 18);
      box(L+W*0.55, y, W*0.15, 18);
      box(L+W*0.70, y, W*0.15, 18);
      box(L+W*0.85, y, W*0.075, 18);
      box(L+W*0.925, y, W*0.075, 18);

      lbl(ev.label, L+2, y+2);
      lbl(`Raw (${ev.unit})`, L+W*0.40+2, y+2);
      lbl('Points', L+W*0.55+2, y+2);
      lbl('Pass/Fail', L+W*0.70+2, y+2);
      lbl('GO', L+W*0.85+2, y+2);
      lbl('NO-GO', L+W*0.925+2, y+2);

      val(String(ev.raw||''), L+W*0.40+2, y+9, W*0.15-4);
      val(String(ev.pts||0), L+W*0.55+2, y+9, W*0.15-4);

      if (ev.pts !== undefined) {
        const passColor = pass ? '#c8f7c5' : '#f7c5c5';
        doc.rect(L+W*0.70, y, W*0.15, 18).fill(passColor);
        doc.rect(L+W*0.70, y, W*0.15, 18).stroke('#000');
        doc.fontSize(9).font('Helvetica-Bold').fillColor('#000')
          .text(pass ? 'GO' : 'NO-GO', L+W*0.70+2, y+5, { lineBreak: false });

        if (pass) {
          doc.rect(L+W*0.85, y, W*0.075, 18).fill('#c8f7c5').stroke('#000');
          doc.fontSize(10).font('Helvetica-Bold').fillColor('#000').text('✓', L+W*0.85+8, y+4, { lineBreak: false });
        } else {
          doc.rect(L+W*0.925, y, W*0.075, 18).fill('#f7c5c5').stroke('#000');
          doc.fontSize(10).font('Helvetica-Bold').fillColor('#000').text('✓', L+W*0.925+8, y+4, { lineBreak: false });
        }
      }
      y += 18;
    });

    // Total score row
    y += 4;
    const totalPass2 = total >= (standard === 'combat' ? 350 : 300);
    const totalColor = (overallPass) ? '#c8f7c5' : '#f7c5c5';
    doc.rect(L, y, W, 24).fill(totalColor).stroke('#000');
    doc.fontSize(10).font('Helvetica-Bold').fillColor('#000')
      .text(`TOTAL SCORE: ${total||0} / 500`, L+4, y+4, { lineBreak: false });
    doc.text(`MINIMUM REQUIRED: ${standard === 'combat' ? 350 : 300}`, L+W*0.4, y+4, { lineBreak: false });
    doc.text(overallPass ? '✓ PASS' : '✗ FAIL', L+W*0.75, y+4, { lineBreak: false });
    doc.fillColor('#000');
    y += 28;

    // Signature block
    hdr('SIGNATURES', L, y, W);
    y += 15;

    box(L, y, W*0.5, 30);
    box(L+W*0.5, y, W*0.5, 30);
    lbl('SOLDIER SIGNATURE', L+2, y+2);
    lbl('OIC/NCOIC NAME (Last, First, MI)', L+W*0.5+2, y+2);
    val(oicName||'', L+W*0.5+2, y+14, W*0.5-4);
    y += 30;

    box(L, y, W*0.5, 20);
    box(L+W*0.5, y, W*0.3, 20);
    box(L+W*0.8, y, W*0.2, 20);
    lbl('OIC/NCOIC SIGNATURE', L+2, y+2);
    lbl('DATE', L+W*0.5+2, y+2);
    lbl('OVERALL', L+W*0.8+2, y+2);
    val(overallPass ? 'GO' : 'NO-GO', L+W*0.8+2, y+10, W*0.2-4);
    y += 24;

    // Footer
    doc.fontSize(6).font('Helvetica-Oblique').fillColor('#666')
      .text('NOTE: To convert raw scores to scaled scores, refer to AFT event score conversion tables at https://www.army.mil/aft', L, y, { width: W });
    y += 8;
    doc.text('Generated by NCO Tools | Review all content before official use | DA FORM 705', L, y, { width: W, align: 'center' });

    doc.end();

  } catch (err) {
    console.error('DA 705 PDF error:', err);
    res.status(500).json({ error: 'PDF generation failed: ' + err.message });
  }
});


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
