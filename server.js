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
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();

// Trust Render's proxy so rate limiting works correctly
app.set('trust proxy', 1);

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

// File upload config — memory storage, PDF/DOCX only, 10MB max
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error('Only PDF and DOCX files are allowed'));
  }
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

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

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

// Sanitize user input before sending to AI — strip potential prompt injection attempts
function sanitizeInput(str, maxLen = 2000) {
  if (!str) return '';
  return String(str)
    .replace(/<[^>]*>/g, '') // strip HTML
    .replace(/\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|###\s*(System|User|Assistant):/gi, '') // strip common prompt injection markers
    .trim()
    .substring(0, maxLen);
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

// SEO
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nAllow: /\nSitemap: https://ncokit.com/sitemap.xml`);
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://ncokit.com</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`);
});

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

function checkUsageLimit(deductCount) {
  return async function(req, res, next) {
    const user = await getUserFromSession(req);

    if (!user) {
      const anonCount = parseInt(req.headers['x-anon-usage'] || '0');
      if (anonCount >= 3) {
        return res.status(403).json({ error: 'limit_reached', limitType: 'anonymous' });
      }
      return next();
    }

    if (user.plan === 'premium') return next();

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

    const count = (deductCount === 'bullets')
      ? Math.max(1, parseInt(req.body.count) || 3)
      : (deductCount || 1);

    const used = user.bullets_used_this_month || 0;
    const limit = 10;

    if (used + count > limit) {
      return res.status(403).json({ error: 'limit_reached', limitType: 'free', used, limit, needed: count });
    }

    await pool.query(
      'UPDATE users SET bullets_used_this_month = bullets_used_this_month + $1 WHERE id = $2',
      [count, user.id]
    );

    next();
  };
}


app.post('/api/enhance-counseling', aiLimiter, checkUsageLimit(1), async (req, res) => {
  const { rawText, section, soldierName, rank, counselingType } = req.body;
  if (!rawText) return res.status(400).json({ error: 'Text is required.' });
  const safeText = sanitizeInput(rawText, 1000);
  const safeName = sanitizeInput(soldierName, 100);
  const safeRank = sanitizeInput(rank, 50);
  const safeCounselingType = sanitizeInput(counselingType, 50);
  const sectionContext = {
    situation: 'the Background Information / Purpose of Counseling section',
    strengths: 'the Strengths and Commendable Performance section',
    improvement: 'the Areas Requiring Improvement section',
    plan_of_action: 'the Plan of Action section',
    leader_responsibilities: 'the Leader Responsibilities section'
  };
  const prompt = `You are an expert Army NCO writer specializing in DA Form 4856. Rewrite the following rough notes into professional Army regulatory language for ${sectionContext[section] || 'a DA 4856'}.\n\nSoldier: ${safeRank} ${safeName}\nCounseling Type: ${safeCounselingType}\nRaw Notes: ${safeText}\n\nRules: Write in third person. Professional Army language. No bullet points. No headers. Output ONLY the rewritten text.`;
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

app.post('/api/bullets', aiLimiter, checkUsageLimit('bullets'), async (req, res) => {
  const { name, category, action, impact, count, mos } = req.body;
  if (!action) return res.status(400).json({ error: 'Action field is required.' });
  const safeName = sanitizeInput(name, 100);
  const safeAction = sanitizeInput(action, 1000);
  const safeImpact = sanitizeInput(impact, 500);

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

Soldier: ${safeName||'Soldier'}${mosLabel}
What they did: ${safeAction}
${safeImpact?`Metrics/Impact: ${safeImpact}`:''}

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


// OER Bullet Builder
app.post('/api/oer-bullets', aiLimiter, checkUsageLimit('bullets'), async (req, res) => {
  const { officerName, rank, unit, attribute, accomplishments, count } = req.body;
  if (!attribute || !accomplishments) return res.status(400).json({ error: 'Attribute and accomplishments required.' });
  const attributeGuidance = {
    'Character': 'Army Values (LDRSHIP), empathy, warrior ethos, service ethos, discipline',
    'Presence': 'Military bearing, professional bearing, fitness, confidence, resilience',
    'Intellect': 'Mental agility, sound judgment, innovation, interpersonal tact, domain expertise',
    'Leads': 'Leads others, builds trust, extends influence beyond chain, leads by example, communicates',
    'Develops': 'Creates positive environment, esprit de corps, prepares self, develops others, stewards profession',
    'Achieves': 'Gets results, mission accomplishment, unit performance, decisive action'
  };
  const guidance = attributeGuidance[attribute] || attribute;
  const safeRank = (rank || 'Officer').replace(/[^a-zA-Z0-9 \/]/g, '');
  const safeName = (officerName || '').replace(/[^a-zA-Z0-9 \.'-]/g, '').slice(0, 60);
  const safeUnit = (unit || '').replace(/[^a-zA-Z0-9 \.'-\/]/g, '').slice(0, 80);
  const safeAccomplishments = (accomplishments || '').replace(/<[^>]*>/g, '').slice(0, 2000);
  const prompt = `You are an expert Army officer rater who writes exceptional OER evaluation bullets following AR 623-3 and ADP 6-22.\n\nGenerate exactly ${count||3} OER bullet(s) for the "${attribute}" attribute section.\nAttribute focus: ${guidance}\n\nOfficer: ${safeRank} ${safeName}\nUnit: ${safeUnit}\nAccomplishments: ${safeAccomplishments}\n\nRules:\n- Start each bullet with a strong past-tense action verb\n- Write in third person (never 'I' — use 'Led', 'Managed', 'Directed')\n- Quantify results with numbers, percentages, or timelines where possible\n- Demonstrate the ${attribute} ADP 6-22 attribute\n- Each bullet max 200 characters, 1-2 punchy sentences\n- Do NOT number bullets or add symbols\n- Follow AR 623-3 Army writing standards: active voice, specific accomplishments\n\nRespond with ONLY the bullets, one per line, nothing else.`;
  try {
    const data = await anthropic.messages.create({ model: 'claude-haiku-4-5-20251001', max_tokens: 600, messages: [{ role: 'user', content: prompt }] });
    const bullets = data.content.map(i=>i.text||'').join('').trim().split('\n').map(b=>b.trim()).filter(b=>b.length>0);
    res.json({ bullets });
  } catch(e) { res.status(500).json({ error: 'Generation failed' }); }
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

// Awards Recommendation Writer
app.post('/api/awards', aiLimiter, checkUsageLimit(1), async (req, res) => {
  const { soldierName, rank, unit, awardLevel, period, accomplishments } = req.body;
  if (!accomplishments || !awardLevel) return res.status(400).json({ error: 'Award level and accomplishments are required.' });
  const safeSoldierName = sanitizeInput(soldierName, 100);
  const safeRank = sanitizeInput(rank, 50);
  const safeUnit = sanitizeInput(unit, 100);
  const safePeriod = sanitizeInput(period, 100);
  const safeAccomplishments = sanitizeInput(accomplishments, 3000);

  const awardGuidance = {
    'AAM': {
      name: 'Army Achievement Medal',
      charLimit: 500,
      standard: 'Recognize specific short-term accomplishments. Language should be clear and direct. Quantify impact where possible. One strong paragraph.',
      threshold: 'Local level impact. Section/platoon level accomplishments. Technical proficiency or single notable achievement.'
    },
    'ARCOM': {
      name: 'Army Commendation Medal',
      charLimit: 640,
      standard: 'Recognize sustained superior performance or a specific achievement of significant merit. Should demonstrate clear impact beyond immediate section. Numbers and metrics are critical.',
      threshold: 'Company/battalion level impact. Leadership demonstrated. Measurable results. Sustained performance over time.'
    },
    'MSM': {
      name: 'Meritorious Service Medal',
      charLimit: 750,
      standard: 'Recognize outstanding meritorious service or achievement. Language must reflect senior NCO/officer-level responsibility and impact. Must demonstrate organizational-level results.',
      threshold: 'Battalion/brigade level impact. Significant leadership responsibilities. Exceptional results that elevated unit readiness or capability.'
    },
    'BSM': {
      name: 'Bronze Star Medal',
      charLimit: 750,
      standard: 'Recognize heroic or meritorious achievement or service in connection with military operations against an armed enemy OR meritorious service in a combat zone. Must clearly establish merit.',
      threshold: 'Combat zone service or operations against armed enemy. Exceptional performance under adverse conditions. Life-safety or mission-critical impact.'
    },
    'LOM': {
      name: 'Legion of Merit',
      charLimit: 900,
      standard: 'Recognize exceptionally meritorious conduct in the performance of outstanding services. Language must reflect senior leadership, strategic impact, and lasting organizational improvement.',
      threshold: 'Brigade/division level impact. Senior leadership positions. Strategic contributions. Lasting improvements to Army readiness or capability.'
    }
  };

  const award = awardGuidance[awardLevel];

  const prompt = `You are an expert Army awards writer with deep knowledge of AR 600-8-22 (Military Awards) and Army writing standards. You write award packages that get approved.

Award: ${award.name} (${awardLevel})
Soldier: ${safeRank} ${safeSoldierName}
Unit: ${safeUnit || 'Not specified'}
Period of Service: ${safePeriod || 'Not specified'}
Award Standard: ${award.standard}
Citation Character Limit: ${award.charLimit} characters

Accomplishments provided by the nominating NCO:
${safeAccomplishments}

YOUR TASKS:

1. BULLETS: Rewrite each accomplishment as a standalone Army-standard bullet in NCOER style.
   - Start with a strong action verb
   - Active voice, third person, never use "I"
   - Quantify with specific numbers, percentages, dollar amounts, timeframes
   - Each bullet under 175 characters
   - Rank bullets strongest to weakest — most impactful first
   - Do NOT number them or add bullet symbols

2. CITATION: Write a single narrative paragraph using those bullets as source material.
   - Opens with "For [meritorious service/outstanding achievement] from [period]..."
   - Flows naturally as connected sentences, not a list
   - CRITICAL: Must be STRICTLY under ${award.charLimit} characters. Count carefully. If needed, cut less impactful content to stay under the limit. Do NOT exceed ${award.charLimit} characters under any circumstance.
   - Closes connecting the soldier's service to Army readiness and values
   - Ready for direct IPPSA submission

3. SCORE: Rate the overall award package 1-10 based on quantification, active voice, and appropriateness for ${awardLevel} level.

4. ADVISORY: Provide 2-3 specific actionable recommendations. If accomplishments are too weak for ${awardLevel} say so directly. Reference specific bullets.

Format your response EXACTLY as:
BULLETS:
[bullet 1]
[bullet 2]
[etc]

CITATION:
[citation paragraph]

SCORE: [X/10]

ADVISORY:
[advisory text]`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 2000, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });

    const text = data.content.map(i => i.text || '').join('').trim();

    // Parse the structured response
    const bulletsMatch = text.match(/BULLETS:\s*([\s\S]*?)(?=CITATION:|$)/i);
    const citationMatch = text.match(/CITATION:\s*([\s\S]*?)(?=SCORE:|$)/i);
    const scoreMatch = text.match(/SCORE:\s*(\d+\/10|\d+)/i);
    const advisoryMatch = text.match(/ADVISORY:\s*([\s\S]*?)$/i);

    const bulletsRaw = bulletsMatch ? bulletsMatch[1].trim() : '';
    const bullets = bulletsRaw.split('\n').map(b => b.trim()).filter(b => b.length > 0);
    let citation = citationMatch ? citationMatch[1].trim() : text;
    
    // Safety net — truncate at last complete sentence if over limit
    if (citation.length > award.charLimit) {
      citation = citation.substring(0, award.charLimit);
      const lastPeriod = citation.lastIndexOf('.');
      if (lastPeriod > award.charLimit * 0.7) citation = citation.substring(0, lastPeriod + 1);
    }
    
    const score = scoreMatch ? scoreMatch[1].trim() : null;
    const advisory = advisoryMatch ? advisoryMatch[1].trim() : null;
    const charCount = citation.length;
    const charLimit = award.charLimit;

    res.json({ bullets, citation, score, advisory, charCount, charLimit, awardName: award.name });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
});

// Senior Rater Narrative
app.post('/api/senior-rater', aiLimiter, checkUsageLimit(1), async (req, res) => {
  const { evalType, name, rank, promotion, schooling, enumeration, nextLevel } = req.body;
  if (!enumeration) return res.status(400).json({ error: 'Peer ranking (Enumeration) is required.' });

  const safeName   = sanitizeInput(name, 100);
  const safeRank   = sanitizeInput(rank, 50);
  const safePromo  = sanitizeInput(promotion, 100);
  const safeSchool = sanitizeInput(schooling, 100);
  const safeEnum   = sanitizeInput(enumeration, 200);
  const safeNext   = sanitizeInput(nextLevel, 200);

  const isOER     = (evalType === 'OER');
  const evalLabel = isOER ? 'OER (Officer Evaluation Report)' : 'NCOER (Non-Commissioned Officer Evaluation Report)';

  const ncoerNextRank = { SGT:'SSG', SSG:'SFC', SFC:'MSG/1SG', MSG:'1SG', '1SG':'SGM/CSM', SGM:'CSM', CSM:'SMA' };
  const oerNextRank   = { '2LT':'1LT', '1LT':'CPT', CPT:'MAJ', MAJ:'LTC', LTC:'COL' };
  const nextRank      = isOER ? (oerNextRank[safeRank] || 'the next grade') : (ncoerNextRank[safeRank] || 'the next grade');

  // Promotion-level guidance injected into the prompt — drives tone and urgency per AR 623-3
  const promoGuide = {
    'Most Qualified': `MOST QUALIFIED — Top ~23% of the senior rater's population. This is the highest rating possible.
Tone: MAXIMUM urgency. Superlative language. This soldier stands above all contemporaries and demands immediate action from the Army.
Sentence 2 guidance: Use language like "stands above all peers in my population," "exceptional potential," "ready to perform two levels above current grade." The language must convey that waiting to act would be a mistake.
Sentence 3 (school): Use: "Send to ${safeSchool} immediately — do not delay." or "Select for ${safeSchool} without hesitation."
Sentence 4 (promote): Use: "Promote to ${nextRank} immediately." or "Promote now — do not pass over this soldier."
Sentence 5 (assignment): Use: "Provide ${safeNext || 'a key leadership position'} now — this soldier is ready." or "Assign to ${safeNext} immediately."`,

    'Highly Qualified': `HIGHLY QUALIFIED — Above center of mass. Ready for promotion ahead of peers.
Tone: Confident and strong, but not superlative. This soldier is ahead of contemporaries and should be promoted before peers.
Sentence 2 guidance: Use language like "above peers in potential," "demonstrates the competence and judgment for ${nextRank}-level responsibilities," "ready for increased responsibility."
Sentence 3 (school): Use: "Send to ${safeSchool}." or "Select for ${safeSchool} — ready for this level of PME."
Sentence 4 (promote): Use: "Promote to ${nextRank} ahead of peers." or "Recommend promotion to ${nextRank}."
Sentence 5 (assignment): Use: "Assign to ${safeNext || 'a broadening position'} — will succeed." or "Provide ${safeNext} — ready for this assignment."`,

    'Qualified': `QUALIFIED — Center of mass. Meets all standards. Developing steadily toward promotion.
Tone: Measured and supportive. Do NOT use urgency language. This is an average positive rating — the narrative should reflect solid but not exceptional standing.
Sentence 2 guidance: Use language like "meets standards," "developing steadily toward ${nextRank}-level responsibilities," "demonstrates the fundamentals needed for future promotion."
Sentence 3 (school): Use: "Recommend for ${safeSchool} when eligible." or "Should attend ${safeSchool} before next promotion."
Sentence 4 (promote): Use: "Will be competitive for promotion to ${nextRank}." or "Recommend for promotion to ${nextRank} when fully qualified."
Sentence 5 (assignment): Use: "Will benefit from continued service in ${safeNext || 'developmental assignments'}." or "Place in ${safeNext} to continue development."`,

    'Not Qualified': `NOT QUALIFIED — Below center of mass. Not ready for promotion this evaluation period.
Tone: Honest and direct. No promotion urgency. Narrative must address what development is needed.
Sentence 2 guidance: Acknowledge where development is required before the next grade. Be specific and honest.
Sentence 3 (school): Reference school as a developmental step, not an immediate reward: "Must complete ${safeSchool} before further consideration."
Sentence 4 (promote): Use: "Not recommended for promotion to ${nextRank} at this time."
Sentence 5 (assignment): Recommend assignment targeting the developmental gap.`
  };

  const guidance = promoGuide[safePromo] || promoGuide['Qualified'];

  const prompt = `You are writing the Senior Rater narrative block for a U.S. Army ${evalLabel} per AR 623-3 (Evaluation Reporting System).

DOCTRINAL REQUIREMENT (AR 623-3): The Senior Rater assesses POTENTIAL only — future capability, readiness for promotion, and assignment potential. Performance is the Rater's domain. Every sentence must be forward-looking.

INPUTS:
- Rated Individual: ${safeRank} ${safeName || '[Soldier]'}
- Enumeration (peer standing): ${safeEnum}
- School Recommendation: ${safeSchool}
- Promotion Recommendation: ${safePromo}
- Next Level Assignment: ${safeNext || 'key leadership assignment'}

===== PROMOTION LEVEL GUIDANCE — THIS CONTROLS YOUR ENTIRE TONE =====
${guidance}
======================================================================

CONSISTENCY RULE: The enumeration ("${safeEnum}") and the promotion recommendation ("${safePromo}") must tell the same story. A high ranking (e.g., "1 of 3") with Most Qualified = maximum urgency throughout. A lower ranking (e.g., "4 of 5") with Qualified = measured language throughout. Do not let these contradict.

OUTPUT — Write exactly 5 sentences in this order:
1. ENUMERATION: Copy this verbatim as Sentence 1: "${safeEnum}"
2. POTENTIAL: One sentence on future potential — calibrated to the promotion level above.
3. SCHOOL: Direct ${safeSchool} recommendation — tone per promotion level above.
4. PROMOTION: Direct ${nextRank} recommendation — tone per promotion level above.
5. NEXT LEVEL: Direct ${safeNext || 'next assignment'} recommendation — tone per promotion level above.

HARD RULES:
- Third person only — never "I"
- No "I recommend," "I believe," or "I suggest"
- Sentence 1 must appear verbatim exactly as given
- Return ONLY the 5-sentence paragraph — no labels, headers, or explanations`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 450, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const narrative = data.content.map(i => i.text || '').join('').trim();
    res.json({ narrative });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
});

// Memo AI Enhancement
app.post('/api/memo-enhance', aiLimiter, checkUsageLimit(1), async (req, res) => {
  const { body, subject, type } = req.body;
  if (!body) return res.status(400).json({ error: 'Body is required.' });

  const safeBody = sanitizeInput(body, 3000);
  const safeSubject = sanitizeInput(subject, 200);

  const prompt = `You are an expert Army staff officer and writer with deep knowledge of AR 25-50 (Army Writing Standards). Rewrite the following content into a properly formatted Army memorandum body.

Memo Type: ${type === 'MFR' ? 'Memorandum For Record' : 'Memorandum For'}
Subject: ${safeSubject}

Content to rewrite:
${safeBody}

Rules for Army memo body:
- Write in clear, direct Army language per AR 25-50
- Use short sentences and active voice
- Third person throughout
- Each major point becomes a separate numbered paragraph (1., 2., 3.)
- Sub-points use lettered subparagraphs (a., b., c.)
- No bullet points — use numbered paragraphs only
- Be factual and precise — include all relevant details from the input
- Do not add information that wasn't provided
- End with a POC paragraph if appropriate: "POC for this memorandum is [leave blank for user to fill]"
- Output ONLY the body paragraphs, no headers or signature block
- Each paragraph on its own line, separated by blank lines`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const enhanced = data.content.map(i => i.text || '').join('').trim();
    res.json({ enhanced });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reach AI service.' });
  }
});

// Memo PDF Generation — AR 25-50 compliant formatting
app.post('/api/generate-memo', (req, res) => {
  const { type, formattedDate, office, unit, addr1, addr2, memoFor, memoThru, subject, formattedBody, sigName, sigRank, sigTitle, sigUnit } = req.body;

  const doc = new PDFDocument({ margin: 72, size: 'letter' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="Memorandum.pdf"`);
  doc.pipe(res);

  const pageW = 612;
  const pageH = 792;
  const marginL = 72;
  const marginR = 72;
  const contentW = pageW - marginL - marginR;
  const marginT = 72;

  // ── LETTERHEAD HEADER ──────────────────────────────────────────────────────
  // Line 1: DEPARTMENT OF THE ARMY — bold centered
  doc.fontSize(12).font('Helvetica-Bold')
    .text('DEPARTMENT OF THE ARMY', marginL, marginT, { width: contentW, align: 'center' });
  let y = doc.y + 2;

  // Line 2: Unit name — centered
  if (unit) {
    doc.fontSize(10).font('Helvetica')
      .text(unit, marginL, y, { width: contentW, align: 'center' });
    y = doc.y + 2;
  }

  // Line 3: Address line 1 — centered
  if (addr1) {
    doc.fontSize(10).font('Helvetica')
      .text(addr1, marginL, y, { width: contentW, align: 'center' });
    y = doc.y + 2;
  }

  // Line 4: City, State ZIP — centered
  if (addr2) {
    doc.fontSize(10).font('Helvetica')
      .text(addr2, marginL, y, { width: contentW, align: 'center' });
    y = doc.y + 2;
  }

  // Horizontal rule under letterhead
  y += 6;
  doc.moveTo(marginL, y).lineTo(pageW - marginR, y).lineWidth(1).stroke();
  y += 14;

  // ── OFFICE SYMBOL (left) and DATE (right) on same line ────────────────────
  const dateStr = formattedDate || '';
  if (office) {
    doc.fontSize(10).font('Helvetica').fillColor('#000000').text(office, marginL, y);
  }
  const dateTextWidth = doc.fontSize(10).font('Helvetica').widthOfString(dateStr);
  doc.fontSize(10).font('Helvetica').text(dateStr, pageW - marginR - dateTextWidth, y);
  y += 20;

  // ── THRU LINE ──────────────────────────────────────────────────────────────
  if (type === 'MEMO_THRU' && memoThru) {
    doc.fontSize(10).font('Helvetica-Bold').text('MEMORANDUM THRU', marginL, y);
    y = doc.y + 2;
    doc.fontSize(10).font('Helvetica').text(memoThru, marginL + 18, y, { width: contentW - 18 });
    y = doc.y + 8;
  }

  // ── MEMORANDUM FOR LINE ────────────────────────────────────────────────────
  if (type === 'MFR') {
    doc.fontSize(10).font('Helvetica-Bold').text('MEMORANDUM FOR RECORD', marginL, y);
  } else {
    doc.fontSize(10).font('Helvetica-Bold').text('MEMORANDUM FOR', marginL, y, { continued: true });
    doc.font('Helvetica').text(`  ${memoFor || ''}`, { width: contentW });
  }
  y = doc.y + 8;

  // ── SUBJECT LINE ───────────────────────────────────────────────────────────
  doc.fontSize(10).font('Helvetica-Bold').text('SUBJECT:', marginL, y, { continued: true });
  doc.font('Helvetica').text(`  ${subject || ''}`, { width: contentW });
  y = doc.y + 16;

  // ── BODY ───────────────────────────────────────────────────────────────────
  if (formattedBody) {
    const paragraphs = formattedBody.split('\n\n').filter(p => p.trim());
    for (const para of paragraphs) {
      const text = para.trim();
      if (!text) continue;
      if (y > pageH - 200) { doc.addPage(); y = marginT; }
      doc.fontSize(10).font('Helvetica').fillColor('#000000')
        .text(text, marginL, y, { width: contentW, align: 'left', lineGap: 2 });
      y = doc.y + 12;
    }
  }

  // ── SIGNATURE BLOCK ────────────────────────────────────────────────────────
  y = Math.max(y + 20, pageH - 160);
  if (y > pageH - 120) { doc.addPage(); y = marginT + 200; }

  const sigX = marginL + (contentW * 0.5);
  doc.fontSize(10).font('Helvetica').fillColor('#000000')
    .text('_'.repeat(30), sigX, y, { characterSpacing: 1 });
  y = doc.y + 4;

  if (sigName) {
    doc.fontSize(10).font('Helvetica-Bold').text(sigName.toUpperCase(), sigX, y);
    y = doc.y + 2;
  }
  if (sigRank) { doc.fontSize(10).font('Helvetica').text(sigRank, sigX, y); y = doc.y + 2; }
  if (sigTitle) { doc.fontSize(10).font('Helvetica').text(sigTitle, sigX, y); y = doc.y + 2; }
  if (sigUnit) { doc.fontSize(10).font('Helvetica').text(sigUnit, sigX, y); }

  // ── FOOTER ─────────────────────────────────────────────────────────────────
  doc.fontSize(7).font('Helvetica').fillColor('#888888')
    .text('Generated by NCO Kit — ncokit.com | Review before official use | Not an official Army document',
      marginL, pageH - 30, { width: contentW, align: 'center' });

  doc.end();
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

// OER Category Validation
app.post('/api/validate-oer-category', aiLimiter, async (req, res) => {
  const { bullets, attribute } = req.body;
  if (!bullets || !attribute) return res.json({ suggestion: null });
  const prompt = `You are an Army OER expert familiar with ADP 6-22 and AR 623-3. A rater placed these bullets in the "${attribute}" section of an OER.\n\nBullets:\n${bullets.join('\n')}\n\nDetermine if a different ADP 6-22 attribute (Character, Presence, Intellect, Leads, Develops, or Achieves) would be significantly more appropriate.\n\nIf yes, respond with one short sentence starting with "These bullets describe" and ending with the better attribute name. Example: "These bullets describe mission accomplishment — consider moving them to Achieves instead."\n\nIf the current attribute is appropriate, respond with exactly: ok\n\nRespond with ONLY that one sentence or ok. No other text.`;
  try {
    const data = await anthropic.messages.create({ model: 'claude-haiku-4-5-20251001', max_tokens: 80, messages: [{ role: 'user', content: prompt }] });
    const suggestion = data.content.map(i=>i.text||'').join('').trim();
    res.json({ suggestion: suggestion === 'ok' ? null : suggestion });
  } catch(e) { res.json({ suggestion: null }); }
});

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

// Save OER bullets
app.post('/api/save/oer-bullet', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { officerName, rank, unit, attribute, bullets } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO saved_oer_bullets (user_id, officer_name, rank, unit, attribute, bullets) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [user.id, officerName, rank, unit, attribute, JSON.stringify(bullets)]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch(e) { res.status(500).json({ error: 'Save failed' }); }
});
// Get saved OER bullets
app.get('/api/save/oer-bullets', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query('SELECT * FROM saved_oer_bullets WHERE user_id = $1 ORDER BY created_at DESC', [user.id]);
    res.json({ bullets: result.rows });
  } catch(e) { res.status(500).json({ error: 'Load failed' }); }
});
// Delete saved OER bullet
app.delete('/api/save/oer-bullet/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_oer_bullets WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Delete failed' }); }
});

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

// Save award citation
app.post('/api/save/award', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { soldierName, rank, unit, awardLevel, period, citation, score } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO saved_awards (user_id, soldier_name, rank, unit, award_level, period, citation, score) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [user.id, soldierName, rank, unit, awardLevel, period, citation, score]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save' });
  }
});

app.get('/api/save/awards', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_awards WHERE user_id = $1 ORDER BY created_at DESC',
      [user.id]
    );
    res.json({ awards: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

app.delete('/api/save/award/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_awards WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});


// ── DOCUMENT UPLOAD & MANAGEMENT ─────────────────────────────────────────────

app.post('/api/save/document', upload.single('file'), async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { soldierName } = req.body;
  const { originalname, mimetype, buffer } = req.file;
  try {
    let extractedText = '';
    if (mimetype === 'application/pdf') {
      const parsed = await pdfParse(buffer);
      extractedText = parsed.text;
    } else {
      const result = await mammoth.extractRawText({ buffer });
      extractedText = result.value;
    }
    if (!extractedText.trim()) {
      return res.status(422).json({ error: 'Could not extract text from this file. Make sure it is not a scanned image.' });
    }
    const fileType = mimetype === 'application/pdf' ? 'pdf' : 'docx';
    const result = await pool.query(
      'INSERT INTO saved_documents (user_id, soldier_name, filename, file_type, extracted_text) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [user.id, soldierName || '', originalname, fileType, extractedText.substring(0, 50000)]
    );
    res.json({ success: true, id: result.rows[0].id, charCount: extractedText.length });
  } catch (err) {
    console.error('Document upload error:', err);
    res.status(500).json({ error: 'Failed to process document' });
  }
});

app.get('/api/save/documents', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name } = req.query;
  try {
    const query = name
      ? 'SELECT id, soldier_name, filename, file_type, created_at FROM saved_documents WHERE user_id = $1 AND LOWER(soldier_name) LIKE $2 ORDER BY created_at DESC'
      : 'SELECT id, soldier_name, filename, file_type, created_at FROM saved_documents WHERE user_id = $1 ORDER BY created_at DESC';
    const params = name ? [user.id, '%' + name.toLowerCase() + '%'] : [user.id];
    const result = await pool.query(query, params);
    res.json({ documents: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load documents' });
  }
});

app.get('/api/save/document/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const result = await pool.query(
      'SELECT * FROM saved_documents WHERE id = $1 AND user_id = $2',
      [req.params.id, user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ document: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load' });
  }
});

app.delete('/api/save/document/:id', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await pool.query('DELETE FROM saved_documents WHERE id = $1 AND user_id = $2', [req.params.id, user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

app.post('/api/analyze-document', aiLimiter, checkUsageLimit(1), async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { documentId, analysisType, soldierName, rank } = req.body;
  if (!documentId || !analysisType) return res.status(400).json({ error: 'documentId and analysisType are required' });
  try {
    const docResult = await pool.query(
      'SELECT extracted_text, filename FROM saved_documents WHERE id = $1 AND user_id = $2',
      [documentId, user.id]
    );
    if (docResult.rows.length === 0) return res.status(404).json({ error: 'Document not found' });
    const { extracted_text, filename } = docResult.rows[0];
    const safeText = extracted_text.substring(0, 8000);
    const safeName = sanitizeInput(soldierName, 100) || 'the Soldier';
    const safeRank = sanitizeInput(rank, 50) || '';
    let prompt;
    if (analysisType === 'bullets') {
      prompt = 'You are an expert Army NCO writer. Review the following document and extract the most significant accomplishments. Write 5 strong NCOER-style bullet points.\n\nDocument: "' + filename + '"\nSoldier: ' + safeRank + ' ' + safeName + '\n\nDocument Content:\n' + safeText + '\n\nRules:\n- Start each bullet with a strong action verb\n- Third person, no "I"\n- Quantify with numbers/metrics wherever the document provides them\n- Under 175 characters each\n- Do NOT number the bullets or add symbols\n\nRespond with ONLY the 5 bullets, one per line.';
    } else {
      prompt = 'You are an expert Army awards writer. Review the following document and write a narrative award citation suitable for an Army Commendation Medal (ARCOM).\n\nDocument: "' + filename + '"\nSoldier: ' + safeRank + ' ' + safeName + '\n\nDocument Content:\n' + safeText + '\n\nRules:\n- Opens with "For meritorious service..."\n- Third person throughout\n- Highlight specific measurable impacts\n- Keep strictly under 640 characters\n- Professional Army awards language per AR 600-8-22\n\nRespond with ONLY the citation paragraph.';
    }
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const output = data.content.map(i => i.text || '').join('').trim();
    res.json({ output, analysisType });
  } catch (err) {
    console.error('Analyze document error:', err);
    res.status(500).json({ error: 'Failed to analyze document' });
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

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
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
      counseling_used_this_month INTEGER DEFAULT 0,
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

    // Migrations — add columns if they don't exist
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS counseling_used_this_month INTEGER DEFAULT 0`);
    await pool.query(`CREATE TABLE IF NOT EXISTS saved_awards (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      soldier_name VARCHAR(255),
      rank VARCHAR(50),
      unit VARCHAR(255),
      award_level VARCHAR(20),
      period VARCHAR(100),
      citation TEXT,
      score VARCHAR(20),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_awards_user ON saved_awards(user_id)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS saved_oer_bullets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      officer_name TEXT,
      rank TEXT,
      unit TEXT,
      attribute TEXT,
      bullets JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_oer_bullets_user ON saved_oer_bullets(user_id)`);

        await pool.query(`CREATE TABLE IF NOT EXISTS saved_documents (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      soldier_name VARCHAR(255),
      filename VARCHAR(500),
      file_type VARCHAR(20),
      extracted_text TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_documents_user ON saved_documents(user_id)`);

    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database init error:', err.message);
  }
}

// Contact form
app.post('/api/contact', authLimiter, async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  // Basic sanitization — strip HTML tags from inputs
  const sanitize = str => String(str).replace(/<[^>]*>/g, '').substring(0, 2000);
  const safeName = sanitize(name);
  const safeSubject = sanitize(subject);
  const safeMessage = sanitize(message);
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: 'NCO Kit Contact <noreply@ncokit.com>',
        to: 'brighamwilsonjr@gmail.com',
        reply_to: email,
        subject: `[NCO Kit] ${safeSubject} — from ${safeName}`,
        html: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:40px 20px;background:#0d0f0d;color:#F4F1EA;">
            <h1 style="color:#C8B48A;font-size:20px;letter-spacing:3px;text-transform:uppercase;margin-bottom:4px;">NCO Kit</h1>
            <h2 style="color:#F4F1EA;font-size:16px;margin-bottom:24px;border-bottom:1px solid #2B3A2E;padding-bottom:12px;">New Contact Form Submission</h2>
            <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
              <tr>
                <td style="padding:8px 12px;color:#a08e65;font-size:12px;width:100px;vertical-align:top;">FROM</td>
                <td style="padding:8px 12px;color:#F4F1EA;font-size:14px;">${safeName}</td>
              </tr>
              <tr style="background:#1a2419;">
                <td style="padding:8px 12px;color:#a08e65;font-size:12px;vertical-align:top;">EMAIL</td>
                <td style="padding:8px 12px;color:#F4F1EA;font-size:14px;"><a href="mailto:${email}" style="color:#C8B48A;">${email}</a></td>
              </tr>
              <tr>
                <td style="padding:8px 12px;color:#a08e65;font-size:12px;vertical-align:top;">SUBJECT</td>
                <td style="padding:8px 12px;color:#F4F1EA;font-size:14px;">${safeSubject}</td>
              </tr>
            </table>
            <div style="background:#1a2419;padding:20px;border-left:3px solid #C8B48A;margin-bottom:24px;">
              <div style="color:#a08e65;font-size:11px;letter-spacing:2px;margin-bottom:10px;">MESSAGE</div>
              <div style="color:#F4F1EA;font-size:14px;line-height:1.7;white-space:pre-wrap;">${safeMessage}</div>
            </div>
            <p style="color:#666;font-size:11px;">Reply directly to this email to respond to ${safeName}.</p>
          </div>
        `
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(data));
    res.json({ success: true });
  } catch (err) {
    console.error('Contact form error:', err.message);
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// Admin route to gift premium access
app.post('/api/admin/gift-premium', async (req, res) => {
  const { secret, email } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  try {
    const result = await pool.query(
      'UPDATE users SET plan = $1, updated_at = NOW() WHERE email = $2 RETURNING email',
      ['premium', email.toLowerCase()]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `${email} granted premium access` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Soldier Profile — all records for a soldier by name
app.get('/api/save/soldier-profile', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'Soldier name required' });
  const search = '%' + name.toLowerCase() + '%';
  try {
    const [c, b, a, aw] = await Promise.all([
      pool.query('SELECT id, date, counseling_type, subject, created_at FROM saved_counselings WHERE user_id=$1 AND LOWER(soldier_name) LIKE $2 ORDER BY created_at DESC', [user.id, search]),
      pool.query('SELECT id, category, bullets, created_at FROM saved_bullets WHERE user_id=$1 AND LOWER(soldier_name) LIKE $2 ORDER BY created_at DESC', [user.id, search]),
      pool.query('SELECT id, test_date, standard, total, pass_fail, created_at FROM saved_aft_scores WHERE user_id=$1 AND LOWER(soldier_name) LIKE $2 ORDER BY created_at DESC', [user.id, search]),
      pool.query('SELECT id, award_level, period, created_at FROM saved_awards WHERE user_id=$1 AND LOWER(soldier_name) LIKE $2 ORDER BY created_at DESC', [user.id, search])
    ]);
    res.json({ name, counselings: c.rows, bullets: b.rows, aft: a.rows, awards: aw.rows });
  } catch (err) {
    console.error('Soldier profile error:', err);
    res.status(500).json({ error: 'Failed to load soldier profile' });
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
