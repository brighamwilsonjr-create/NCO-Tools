const express = require('express');
const cors = require('cors');
const path = require('path');
const PDFDocument = require('pdfkit');
const { calculateAFT } = require('./aft_tables');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const rateLimit = require('express-rate-limit');

const app = express();

// CORS — restrict to ncokit.com only
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://ncokit.com', 'https://www.ncokit.com']
    : '*',
  credentials: true
}));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests. Please try again shortly.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply general limiter to all routes
app.use(generalLimiter);

// Stripe webhook needs raw body BEFORE express.json()
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.metadata?.userId;
      const customerId = session.customer;
      const subscriptionId = session.subscription;
      if (userId) {
        await pool.query(
          'UPDATE users SET plan = $1, stripe_customer_id = $2, stripe_subscription_id = $3, updated_at = NOW() WHERE id = $4',
          ['premium', customerId, subscriptionId, userId]
        );
        const userResult = await pool.query('SELECT referred_by FROM users WHERE id = $1', [userId]);
        const referredBy = userResult.rows[0]?.referred_by;
        if (referredBy) {
          await pool.query(
            'UPDATE users SET free_months_earned = free_months_earned + 1 WHERE referral_code = $1',
            [referredBy]
          );
        }
        console.log(`User ${userId} upgraded to premium`);
      }
    }
    if (event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object;
      await pool.query(
        'UPDATE users SET plan = $1, stripe_subscription_id = NULL, updated_at = NOW() WHERE stripe_subscription_id = $2',
        ['free', subscription.id]
      );
      console.log(`Subscription ${subscription.id} cancelled`);
    }
    if (event.type === 'invoice.payment_failed') {
      console.log(`Payment failed for customer ${event.data.object.customer}`);
    }
  } catch (err) {
    console.error('Webhook processing error:', err);
  }
  res.json({ received: true });
});

// Body size limit — 10kb max
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Clean up expired sessions periodically
async function cleanupSessions() {
  try {
    const result = await pool.query('DELETE FROM sessions WHERE expires_at < NOW()');
    if (result.rowCount > 0) console.log(`Cleaned up ${result.rowCount} expired sessions`);
  } catch (err) {
    console.error('Session cleanup error:', err.message);
  }
}


// Email via Resend REST API - no SDK needed
async function sendEmail(to, subject, html) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`
    },
    body: JSON.stringify({ from: 'NCO Kit <noreply@ncokit.com>', to, subject, html })
  });
  const data = await response.json();
  console.log('Resend response:', JSON.stringify(data));
  if (!response.ok) throw new Error(`Email failed: ${JSON.stringify(data)}`);
  return data;
}

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function generateReferralCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

async function getUserFromSession(req) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return null;
  const result = await pool.query(
    `SELECT u.id, u.email, u.plan, u.verified, u.referral_code, u.referred_by,
            u.stripe_customer_id, u.stripe_subscription_id, u.bullets_used_this_month,
            u.bullets_reset_date, u.free_months_earned, u.free_months_used
     FROM users u JOIN sessions s ON s.user_id = u.id
     WHERE s.token = $1 AND s.expires_at > NOW()`,
    [token]
  );
  return result.rows[0] || null;
}

async function sendVerificationEmail(email, token) {
  const verifyUrl = `https://ncokit.com/verify?token=${token}`;
  await sendEmail(email, 'Verify your NCO Kit account', `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:40px 20px;background:#0d0f0d;color:#F4F1EA;">
      <h1 style="color:#C8B48A;font-size:24px;letter-spacing:4px;text-transform:uppercase;">NCO Kit</h1>
      <h2 style="color:#F4F1EA;">Verify Your Email</h2>
      <p style="color:#a08e65;font-size:14px;line-height:1.6;">Click below to verify your email and activate your account.</p>
      <a href="${verifyUrl}" style="display:inline-block;margin:24px 0;padding:14px 32px;background:#C8B48A;color:#1a2419;font-weight:bold;text-decoration:none;letter-spacing:2px;text-transform:uppercase;font-size:13px;">Verify Email</a>
      <p style="color:#666;font-size:12px;">This link expires in 24 hours.</p>
      <p style="color:#666;font-size:11px;">Or copy: ${verifyUrl}</p>
    </div>
  `);
}

async function sendPasswordResetEmail(email, token) {
  const resetUrl = `https://ncokit.com/reset-password?token=${token}`;
  await sendEmail(email, 'Reset your NCO Kit password', `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:40px 20px;background:#0d0f0d;color:#F4F1EA;">
      <h1 style="color:#C8B48A;font-size:24px;letter-spacing:4px;text-transform:uppercase;">NCO Kit</h1>
      <h2 style="color:#F4F1EA;">Reset Your Password</h2>
      <p style="color:#a08e65;font-size:14px;line-height:1.6;">Click below to reset your password. Expires in 1 hour.</p>
      <a href="${resetUrl}" style="display:inline-block;margin:24px 0;padding:14px 32px;background:#C8B48A;color:#1a2419;font-weight:bold;text-decoration:none;letter-spacing:2px;text-transform:uppercase;font-size:13px;">Reset Password</a>
      <p style="color:#666;font-size:12px;">If you didn't request this, ignore this email.</p>
    </div>
  `);
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => res.json({ status: 'online' }));

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, referredBy } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'An account with this email already exists' });
    const passwordHash = await bcrypt.hash(password, 12);
    const verificationToken = generateToken();
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const referralCode = generateReferralCode();
    let validReferredBy = null;
    if (referredBy) {
      const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referredBy.toUpperCase()]);
      if (referrer.rows.length > 0) validReferredBy = referredBy.toUpperCase();
    }
    await pool.query(
      `INSERT INTO users (email, password_hash, verification_token, verification_expires, referral_code, referred_by) VALUES ($1, $2, $3, $4, $5, $6)`,
      [email.toLowerCase(), passwordHash, verificationToken, verificationExpires, referralCode, validReferredBy]
    );
    try {
      await sendVerificationEmail(email.toLowerCase(), verificationToken);
    } catch (emailErr) {
      console.error('Verification email failed:', emailErr.message);
    }
    res.json({ success: true, message: 'Account created. Check your email to verify your account.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const result = await pool.query(
      'SELECT id FROM users WHERE verification_token = $1 AND verification_expires > NOW() AND verified = FALSE',
      [token]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired verification link' });
    await pool.query('UPDATE users SET verified = TRUE, verification_token = NULL, verification_expires = NULL WHERE id = $1', [result.rows[0].id]);
    res.json({ success: true, message: 'Email verified. You can now log in.' });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    if (!user.verified) return res.status(401).json({ error: 'Please verify your email before logging in', needsVerification: true });
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid email or password' });
    const sessionToken = generateToken();
    const sessionExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.query('INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)', [user.id, sessionToken, sessionExpires]);
    res.json({
      success: true,
      token: sessionToken,
      user: { id: user.id, email: user.email, plan: user.plan, referralCode: user.referral_code, bulletsUsed: user.bullets_used_this_month }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (token) await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const user = await getUserFromSession(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    res.json({ id: user.id, email: user.email, plan: user.plan, referralCode: user.referral_code, bulletsUsed: user.bullets_used_this_month, verified: user.verified });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length > 0) {
      const resetToken = generateToken();
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000);
      await pool.query('UPDATE users SET reset_token = $1, reset_expires = $2 WHERE email = $3', [resetToken, resetExpires, email.toLowerCase()]);
      await sendPasswordResetEmail(email.toLowerCase(), resetToken);
    }
    res.json({ success: true, message: 'If an account exists with that email, a reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const result = await pool.query('SELECT id FROM users WHERE reset_token = $1 AND reset_expires > NOW()', [token]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset link' });
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query('UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2', [passwordHash, result.rows[0].id]);
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [result.rows[0].id]);
    res.json({ success: true, message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const result = await pool.query('SELECT id FROM users WHERE email = $1 AND verified = FALSE', [email.toLowerCase()]);
    if (result.rows.length > 0) {
      const verificationToken = generateToken();
      const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await pool.query('UPDATE users SET verification_token = $1, verification_expires = $2 WHERE email = $3', [verificationToken, verificationExpires, email.toLowerCase()]);
      await sendVerificationEmail(email.toLowerCase(), verificationToken);
    }
    res.json({ success: true, message: 'Verification email sent if account exists.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to resend verification' });
  }
});

// ── USAGE LIMITS ──────────────────────────────────────────────────────────────
// Anonymous: 3 lifetime (localStorage on client)
// Free account: 10/month tracked in DB
// Premium: unlimited

async function checkUsageLimit(req, res, next) {
  const user = await getUserFromSession(req);

  // Not logged in — anonymous usage tracked client-side, server trusts header
  if (!user) {
    const anonCount = parseInt(req.headers['x-anon-usage'] || '0');
    if (anonCount >= 3) {
      return res.status(403).json({ error: 'limit_reached', limitType: 'anonymous' });
    }
    return next();
  }

  // Premium — unlimited
  if (user.plan === 'premium') return next();

  // Free account — 10/month limit
  const now = new Date();
  const resetDate = new Date(user.bullets_reset_date);
  const needsReset = now.getFullYear() > resetDate.getFullYear() ||
    now.getMonth() > resetDate.getMonth();

  if (needsReset) {
    await pool.query(
      'UPDATE users SET bullets_used_this_month = 0, bullets_reset_date = CURRENT_DATE WHERE id = $1',
      [user.id]
    );
    user.bullets_used_this_month = 0;
  }

  if (user.bullets_used_this_month >= 10) {
    return res.status(403).json({ error: 'limit_reached', limitType: 'free', used: user.bullets_used_this_month, limit: 10 });
  }

  // Increment usage
  await pool.query(
    'UPDATE users SET bullets_used_this_month = bullets_used_this_month + 1 WHERE id = $1',
    [user.id]
  );

  next();
}

app.post('/api/enhance-counseling', aiLimiter, checkUsageLimit, async (req, res) => {
  const { rawText, section, soldierName, rank, counselingType } = req.body;
  if (!rawText) return res.status(400).json({ error: 'Text is required.' });
  const sectionContext = {
    situation: 'the Background Information / Purpose of Counseling section',
    strengths: 'the Strengths and Commendable Performance section',
    improvement: 'the Areas Requiring Improvement section',
    plan_of_action: 'the Plan of Action section',
    leader_responsibilities: 'the Leader Responsibilities section'
  };
  const prompt = `You are an expert Army NCO writer specializing in DA Form 4856. Rewrite the following rough notes into professional Army regulatory language for ${sectionContext[section] || 'a DA 4856'}.\n\nSoldier: ${rank} ${soldierName}\nCounseling Type: ${counselingType}\nRaw Notes: ${rawText}\n\nRules: Write in third person. Professional Army language. No bullet points. No headers. Output ONLY the rewritten text.`;
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    res.json({ enhanced: data.content.map(i => i.text || '').join('').trim() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
});

app.post('/api/generate-4856', (req, res) => {
  const { soldierName, rank, date, unit, counselor, counselorRank, subject, situation, strengths, improve, poa, leader } = req.body;
  const doc = new PDFDocument({ margin: 40, size: 'letter' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="DA4856_${(soldierName || 'counseling').replace(/[^a-z0-9]/gi, '_')}.pdf"`);
  doc.pipe(res);
  const W = 595 - 80, L = 40;
  const formattedDate = date ? new Date(date + 'T12:00:00').toLocaleDateString('en-US', { day: '2-digit', month: 'long', year: 'numeric' }) : '___________________';
  const box = (x, y, w, h) => doc.rect(x, y, w, h).stroke();
  const label = (text, x, y, opts = {}) => doc.fontSize(6.5).font('Helvetica').fillColor('#000').text(text, x, y, { ...opts, lineBreak: false });
  const field = (text, x, y, w, opts = {}) => doc.fontSize(9).font('Helvetica').fillColor('#000').text(text || '', x, y, { width: w, ...opts });
  const sHdr = (text, x, y, w) => { doc.rect(x, y, w, 14).fillAndStroke('#000', '#000'); doc.fontSize(8).font('Helvetica-Bold').fillColor('#fff').text(text, x + 4, y + 3, { lineBreak: false }); doc.fillColor('#000'); };
  let y = 40;
  doc.fontSize(10).font('Helvetica-Bold').text('DEVELOPMENTAL COUNSELING FORM', L, y, { align: 'center', width: W }); y += 24;
  sHdr('PART I - ADMINISTRATIVE DATA', L, y, W); y += 16;
  box(L, y, W*.45, 28); box(L+W*.45, y, W*.25, 28); box(L+W*.70, y, W*.30, 28);
  label('Name (Last, First, MI)', L+3, y+2); label('Rank/Grade', L+W*.45+3, y+2); label('Date of Counseling', L+W*.70+3, y+2);
  field(soldierName||'', L+3, y+12, W*.45-6); field(rank||'', L+W*.45+3, y+12, W*.25-6); field(formattedDate, L+W*.70+3, y+12, W*.30-6); y += 28;
  box(L, y, W*.45, 28); box(L+W*.45, y, W*.30, 28); box(L+W*.75, y, W*.25, 28);
  label('Organization', L+3, y+2); label('Name and Title of Counselor', L+W*.45+3, y+2); label('Counselor Rank', L+W*.75+3, y+2);
  field(unit||'', L+3, y+12, W*.45-6); field(counselor||'', L+W*.45+3, y+12, W*.30-6); field(counselorRank||'', L+W*.75+3, y+12, W*.25-6); y += 28;
  sHdr('PART II - BACKGROUND INFORMATION', L, y, W); y += 16;
  box(L, y, W, 24); label('Purpose of Counseling', L+3, y+2); field(subject||'', L+3, y+13, W-6); y += 24;
  const sitH = Math.min(Math.max(Math.ceil((situation||'').length/90)*13, 60), 130);
  box(L, y, W, sitH); label('Key Facts / Background', L+3, y+2); doc.fontSize(8.5).font('Helvetica').text(situation||'', L+3, y+13, { width: W-6, height: sitH-16 }); y += sitH;
  sHdr('PART III - SUMMARY OF COUNSELING', L, y, W); y += 16;
  if (strengths) { const h=Math.min(Math.max(Math.ceil(strengths.length/90)*13,45),100); box(L,y,W,h); label('STRENGTHS',L+3,y+2); doc.fontSize(8.5).font('Helvetica').text(strengths,L+3,y+13,{width:W-6,height:h-16}); y+=h; }
  if (improve) { const h=Math.min(Math.max(Math.ceil(improve.length/90)*13,45),100); box(L,y,W,h); label('AREAS REQUIRING IMPROVEMENT',L+3,y+2); doc.fontSize(8.5).font('Helvetica').text(improve,L+3,y+13,{width:W-6,height:h-16}); y+=h; }
  const poaH=Math.min(Math.max(Math.ceil((poa||'').length/90)*13,60),120); box(L,y,W,poaH); label('Plan of Action',L+3,y+2); doc.fontSize(8.5).font('Helvetica').text(poa||'',L+3,y+13,{width:W-6,height:poaH-16}); y+=poaH;
  const ldrH=Math.min(Math.max(Math.ceil((leader||'').length/90)*13,50),100); box(L,y,W,ldrH); label('Leader Responsibilities',L+3,y+2); doc.fontSize(8.5).font('Helvetica').text(leader||'',L+3,y+13,{width:W-6,height:ldrH-16}); y+=ldrH;
  if(y>680){doc.addPage();y=40;}
  sHdr('PART IV - ASSESSMENT', L, y, W); y+=16;
  box(L,y,W,50); label('[ ] Plan of Action was/was not accomplished.',L+3,y+6); label('Follow-up required: [ ] Yes  [ ] No',L+3,y+18); label('Date of next counseling: _______________',L+3,y+30); y+=54;
  sHdr('SIGNATURES', L, y, W); y+=16;
  box(L,y,W,45); label('INDIVIDUAL COUNSELED — [ ] I agree  [ ] I disagree',L+3,y+2); label('Signature: ________________________________',L+3,y+14); label('Date: ________________',L+W*.6,y+14); y+=45;
  box(L,y,W,40); label('LEADER/COUNSELOR',L+3,y+2); label('Signature: ________________________________',L+3,y+14); label('Date: ________________',L+W*.6,y+14); label(`${counselorRank||''} ${counselor||''}`,L+3,y+28); y+=44;
  doc.fontSize(6).font('Helvetica').fillColor('#666').text('DA FORM 4856 | Generated by NCO Kit — ncokit.com | Review before official use', L, y, { width: W, align: 'center' });
  doc.end();
});

app.post('/api/bullets', aiLimiter, checkUsageLimit, async (req, res) => {
  const { name, category, action, impact, count, mos } = req.body;
  if (!action) return res.status(400).json({ error: 'Action field is required.' });

  const mosContext = {
    '11B': 'Infantryman. Focuses on direct combat operations, small unit tactics, physical readiness, weapons proficiency, and leading soldiers in austere environments.',
    '11C': 'Indirect Fire Infantryman. Focuses on indirect fire support, crew-served weapons, fire mission execution, and supporting maneuver elements.',
    '12B': 'Combat Engineer. Focuses on mobility, countermobility, survivability operations, demolitions, route clearance, and construction support.',
    '13B': 'Cannon Crewmember. Focuses on artillery fire support, howitzer operations, crew drills, ammunition handling, and fire mission execution.',
    '13F': 'Fire Support Specialist. Focuses on coordinating fire support, calling for fires, target acquisition, and integrating combined arms effects.',
    '15W': 'UAS Operator. Focuses on unmanned aircraft operations, reconnaissance missions, sensor employment, and providing ISR support to ground forces.',
    '17C': 'Cyber Operations Specialist. Focuses on cyberspace operations, network defense, vulnerability assessment, and supporting information operations.',
    '19D': 'Cavalry Scout. Focuses on reconnaissance, surveillance, target acquisition, screen operations, and providing battlefield intelligence.',
    '19K': 'M1 Armor Crewman. Focuses on tank gunnery, crew proficiency, maneuver operations, and combined arms integration.',
    '25B': 'IT Specialist. Focuses on network administration, information systems maintenance, cybersecurity, and ensuring communications readiness.',
    '25U': 'Signal Support Systems Specialist. Focuses on communications systems installation, maintenance, and ensuring signal support across the formation.',
    '31B': 'Military Police. Focuses on law enforcement, force protection, area security, detainee operations, and maintaining good order and discipline.',
    '35F': 'Intelligence Analyst. Focuses on all-source intelligence analysis, intelligence preparation of the battlefield, and providing decision-quality intelligence products.',
    '35M': 'HUMINT Collector. Focuses on human intelligence collection, source operations, debriefings, and supporting commander intelligence requirements.',
    '36B': 'Financial Management Technician. Focuses on finance operations, pay support, vendor payments, and ensuring financial accountability.',
    '37F': 'PSYOP Specialist. Focuses on psychological operations planning, target audience analysis, influence activities, and supporting information operations.',
    '38B': 'Civil Affairs Specialist. Focuses on civil-military operations, engagement with local populations and governments, and minimizing civilian impacts.',
    '42A': 'Human Resources Specialist. Focuses on personnel actions, strength management, casualty operations, evaluations, and awards processing.',
    '42T': 'Talent Acquisition Specialist. Focuses on Army recruiting, mission accomplishment, community engagement, and identifying qualified applicants.',
    '68W': 'Combat Medic. Focuses on trauma care, medical readiness, preventive medicine, soldier health, and casualty management.',
    '74D': 'CBRN Specialist. Focuses on chemical, biological, radiological, and nuclear defense operations, detection, and decontamination.',
    '79S': 'Career Counselor. Focuses on soldier retention, career development counseling, reenlistment operations, and force shaping.',
    '88M': 'Motor Transport Operator. Focuses on convoy operations, vehicle operations, load planning, and sustainment movement.',
    '89B': 'Ammunition Specialist. Focuses on ammunition accountability, storage operations, explosives safety, and supporting unit ammunition requirements.',
    '91B': 'Wheeled Vehicle Mechanic. Focuses on vehicle maintenance, diagnostics, repair operations, and ensuring fleet readiness.',
    '92A': 'Automated Logistical Specialist. Focuses on supply operations, property accountability, stock control, and sustainment support.',
    '92F': 'Petroleum Supply Specialist. Focuses on bulk fuel operations, fuel accountability, and ensuring petroleum support to the force.',
    '92G': 'Culinary Specialist. Focuses on food service operations, field feeding, nutritional support, and maintaining food safety standards.',
    '92Y': 'Unit Supply Specialist. Focuses on supply room operations, property accountability, equipment readiness, and logistical support.',
  };

  const mosInfo = mos && mosContext[mos] ? `\nSoldier's Role Context: ${mosContext[mos]}` : '';
  const mosLabel = mos ? ` (${mos})` : '';

  const prompt = `You are an expert Army NCO who writes exceptional NCOER evaluation bullets. Your bullets are concise, action-oriented, and follow Army writing standards.${mosInfo}

Generate exactly ${count||3} NCOER bullet(s) for the "${category}" section of an NCOER.

Soldier: ${name||'Soldier'}${mosLabel}
What they did: ${action}
${impact?`Metrics/Impact: ${impact}`:''}

Rules:
- Start with a strong action verb appropriate to the soldier's role
- Use the MOS context to frame accomplishments correctly — but avoid MOS-specific jargon or acronyms
- Write clean, readable Army language that any promotion board member can understand
- Be specific and measurable where possible
- Use third person — never use "I"
- Each bullet should be one sentence, punchy and direct
- Do NOT use the soldier's name in the bullet
- Format: action verb + what + result/impact
- Keep each bullet under 175 characters
- Do NOT number the bullets or add bullet symbols

Respond with ONLY the bullets, one per line, nothing else.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const bullets = data.content.map(i=>i.text||'').join('').trim().split('\n').map(b=>b.trim()).filter(b=>b.length>0);
    res.json({ bullets });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
});

app.post('/api/aft-score', (req, res) => {
  try {
    res.json(calculateAFT(req.body));
  } catch (err) {
    res.status(500).json({ error: 'Score calculation failed: ' + err.message });
  }
});

// ── STRIPE ENDPOINTS ──────────────────────────────────────────────────────────

app.post('/api/stripe/create-checkout', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  if (user.plan === 'premium') return res.status(400).json({ error: 'Already premium' });

  try {
    let discounts = [];
    if (user.referred_by && !user.stripe_customer_id) {
      const coupon = await stripe.coupons.create({ percent_off: 50, duration: 'once' });
      discounts = [{ coupon: coupon.id }];
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      customer_email: user.email,
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      discounts,
      metadata: { userId: user.id },
      success_url: 'https://ncokit.com/?upgraded=true',
      cancel_url: 'https://ncokit.com/?upgrade=cancelled',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

app.post('/api/stripe/portal', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  if (!user.stripe_customer_id) return res.status(400).json({ error: 'No subscription found' });

  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: 'https://ncokit.com/',
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    res.status(500).json({ error: 'Failed to open billing portal' });
  }
});

// Category fit validation
app.post('/api/validate-category', aiLimiter, async (req, res) => {
  const { bullets, category, action } = req.body;
  if (!bullets || !category) return res.json({ suggestion: null });

  const categoryGuide = `
Character: Army values, ethics, integrity, empathy, warrior ethos, moral courage, discipline, doing what's right
Presence: Physical fitness, military bearing, confidence, resilience, appearance, PT scores, physical readiness
Intellect: Mental agility, innovation, judgment, critical thinking, problem solving, expertise, interpersonal tact
Leads: Leading soldiers, influencing others, building trust, communication, directing teams, motivating people
Develops: Mentoring, creating positive climate, stewardship of resources, self-development, developing subordinates
Achieves: Mission accomplishment, getting results, meeting standards, task completion, operational performance`;

  const prompt = `You are an Army NCOER expert. A leader placed the following bullets in the "${category}" category of an NCOER.

Bullets:
${bullets.join('\n')}

Original description: ${action}

NCOER Category Guide:${categoryGuide}

Analyze whether these bullets fit best in "${category}" or if they would be better placed in a different category.

If the category is correct or close enough, respond with exactly: CORRECT
If a different category would be significantly better, respond with one short sentence starting with "These bullets describe" and ending with the better category name. Example: "These bullets describe physical fitness performance — consider moving them to Presence instead."

Respond with ONLY "CORRECT" or the one-sentence suggestion. Nothing else.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 100, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = data.content?.map(i => i.text || '').join('').trim();
    if (!text || text === 'CORRECT') return res.json({ suggestion: null });
    res.json({ suggestion: text });
  } catch (err) {
    res.json({ suggestion: null });
  }
});



// Save counseling
app.post('/api/save/counseling', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { soldierName, rank, unit, counselor, counselorRank, date, counselingType, subject, situation, strengths, improve, poa, leader } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO saved_counselings (user_id, soldier_name, rank, unit, counselor, counselor_rank, date, counseling_type, subject, situation, strengths, improve, poa, leader)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
      [user.id, soldierName, rank, unit, counselor, counselorRank, date, counselingType, subject, situation, strengths, improve, poa, leader]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Save counseling error:', err);
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Get saved counselings
app.get('/api/save/counselings', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_counselings WHERE user_id = $1 ORDER BY created_at DESC',
      [user.id]
    );
    res.json({ counselings: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

// Delete saved counseling
app.delete('/api/save/counseling/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_counselings WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// Save bullets
app.post('/api/save/bullets', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { soldierName, category, bullets } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO saved_bullets (user_id, soldier_name, category, bullets) VALUES ($1,$2,$3,$4) RETURNING id',
      [user.id, soldierName, category, JSON.stringify(bullets)]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Get saved bullets
app.get('/api/save/bullets', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_bullets WHERE user_id = $1 ORDER BY created_at DESC',
      [user.id]
    );
    res.json({ bullets: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

// Delete saved bullets
app.delete('/api/save/bullets/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_bullets WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// Save AFT score
app.post('/api/save/aft', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { soldierName, age, sex, standard, testDate, mdl, hrp, sdc, plk, tmr, scores, total, overallPass } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO saved_aft_scores (user_id, soldier_name, age, sex, standard, test_date, mdl_raw, hrp_raw, sdc_raw, plk_raw, tmr_raw, mdl_pts, hrp_pts, sdc_pts, plk_pts, tmr_pts, total, pass_fail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id`,
      [user.id, soldierName, age, sex, standard, testDate, mdl, hrp, sdc, plk, tmr, scores?.mdl, scores?.hrp, scores?.sdc, scores?.plk, scores?.tmr, total, overallPass]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Get saved AFT scores
app.get('/api/save/aft', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_aft_scores WHERE user_id = $1 ORDER BY created_at DESC',
      [user.id]
    );
    res.json({ scores: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

// Delete saved AFT score
app.delete('/api/save/aft/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_aft_scores WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// Save soldier to roster
app.post('/api/save/soldier', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name, rank, mos, lastCounseling, status, notes } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO saved_soldiers (user_id, name, rank, mos, last_counseling, status, notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [user.id, name, rank, mos, lastCounseling, status, notes]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

// Get saved soldiers
app.get('/api/save/soldiers', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_soldiers WHERE user_id = $1 ORDER BY name ASC',
      [user.id]
    );
    res.json({ soldiers: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

// Delete saved soldier
app.delete('/api/save/soldier/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_soldiers WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

app.get('/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.redirect('/?error=invalid_token');
  try {
    const result = await pool.query(
      'SELECT id FROM users WHERE verification_token = $1 AND verification_expires > NOW() AND verified = FALSE',
      [token]
    );
    if (result.rows.length === 0) {
      return res.redirect('/?error=invalid_token');
    }
    await pool.query(
      'UPDATE users SET verified = TRUE, verification_token = NULL, verification_expires = NULL WHERE id = $1',
      [result.rows[0].id]
    );
    return res.redirect('/?verified=true');
  } catch (err) {
    console.error('Verify route error:', err);
    return res.redirect('/?error=verify_failed');
  }
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});



async function initDB() {
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      verified BOOLEAN DEFAULT FALSE,
      verification_token VARCHAR(255),
      verification_expires TIMESTAMPTZ,
      reset_token VARCHAR(255),
      reset_expires TIMESTAMPTZ,
      plan VARCHAR(20) DEFAULT 'free',
      stripe_customer_id VARCHAR(255),
      stripe_subscription_id VARCHAR(255),
      referral_code VARCHAR(20) UNIQUE,
      referred_by VARCHAR(20),
      free_months_earned INTEGER DEFAULT 0,
      free_months_used INTEGER DEFAULT 0,
      bullets_used_this_month INTEGER DEFAULT 0,
      bullets_reset_date DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      token VARCHAR(255) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`);

    await pool.query(`CREATE TABLE IF NOT EXISTS saved_counselings (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      soldier_name VARCHAR(255),
      rank VARCHAR(50),
      unit VARCHAR(255),
      counselor VARCHAR(255),
      counselor_rank VARCHAR(50),
      date VARCHAR(50),
      counseling_type VARCHAR(100),
      subject VARCHAR(255),
      situation TEXT,
      strengths TEXT,
      improve TEXT,
      poa TEXT,
      leader TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS saved_bullets (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      soldier_name VARCHAR(255),
      category VARCHAR(100),
      bullets JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS saved_aft_scores (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      soldier_name VARCHAR(255),
      age INTEGER,
      sex VARCHAR(1),
      standard VARCHAR(20),
      test_date VARCHAR(50),
      mdl_raw VARCHAR(20),
      hrp_raw VARCHAR(20),
      sdc_raw VARCHAR(20),
      plk_raw VARCHAR(20),
      tmr_raw VARCHAR(20),
      mdl_pts INTEGER,
      hrp_pts INTEGER,
      sdc_pts INTEGER,
      plk_pts INTEGER,
      tmr_pts INTEGER,
      total INTEGER,
      pass_fail BOOLEAN,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS saved_soldiers (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255),
      rank VARCHAR(50),
      mos VARCHAR(20),
      last_counseling VARCHAR(50),
      status VARCHAR(20),
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_counselings_user ON saved_counselings(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_bullets_user ON saved_bullets(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_aft_user ON saved_aft_scores(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_soldiers_user ON saved_soldiers(user_id)`);

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database init error:', err.message);
  }
}

// Temporary admin route to reset plan for testing
app.post('/api/admin/reset-plan', async (req, res) => {
  const { secret, email } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  try {
    await pool.query(
      'UPDATE users SET plan = $1, stripe_customer_id = NULL, stripe_subscription_id = NULL WHERE email = $2',
      ['free', email.toLowerCase()]
    );
    res.json({ success: true, message: `Reset ${email} to free` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`NCO Kit running on port ${PORT}`);
  await initDB();
  // Clean up expired sessions on start, then every 6 hours
  await cleanupSessions();
  setInterval(cleanupSessions, 6 * 60 * 60 * 1000);
});
