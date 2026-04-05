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
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com https://js.stripe.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com data:; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' https://api.stripe.com https://www.google-analytics.com https://analytics.google.com https://stats.g.doubleclick.net; " +
    "frame-src https://js.stripe.com; " +
    "object-src 'none'; " +
    "base-uri 'self';"
  );
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
        // Unsubscribe from marketing emails in Resend when user upgrades to premium
        const premiumUser = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
        if (premiumUser.rows[0]?.email) {
          fetch(`https://api.resend.com/audiences/${process.env.RESEND_AUDIENCE_ID}/contacts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
            body: JSON.stringify({ email: premiumUser.rows[0].email, unsubscribed: true })
          }).catch(err => console.error('Resend premium update failed:', err.message));
        }
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

async function sendWelcomeEmail(email) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to NCO Kit</title>
</head>
<body style="margin:0;padding:0;background-color:#0a1a0a;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0a1a0a;">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background-color:#0f1f0f;border:1px solid #2a4a2a;border-radius:6px;overflow:hidden;">
          <!-- HEADER -->
          <tr>
            <td style="background-color:#0f1f0f;padding:28px 40px 22px;border-bottom:3px solid #c9a227;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td>
                    <span style="font-size:28px;font-weight:900;color:#c9a227;letter-spacing:2px;text-transform:uppercase;">NCO KIT</span><br>
                    <span style="font-size:11px;color:#7dab7d;letter-spacing:3px;text-transform:uppercase;">ncokit.com &nbsp;·&nbsp; Army Leader's Toolkit</span>
                  </td>
                  <td align="right" style="vertical-align:middle;">
                    <span style="display:inline-block;background-color:#1a3a1a;border:1px solid #c9a227;border-radius:4px;padding:6px 14px;font-size:11px;font-weight:700;color:#c9a227;letter-spacing:2px;text-transform:uppercase;">✓ VERIFIED</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- HERO -->
          <tr>
            <td style="padding:44px 40px 32px;">
              <p style="margin:0 0 6px;font-size:13px;color:#7dab7d;letter-spacing:3px;text-transform:uppercase;">Welcome</p>
              <h1 style="margin:0 0 20px;font-size:34px;font-weight:900;color:#e8e4d4;line-height:1.2;">You're in. Let's get to work.</h1>
              <p style="margin:0;font-size:16px;color:#a8c8a8;line-height:1.7;">
                Your NCO Kit account is active. You now have access to every tool in the kit — counselings, NCOER bullets, awards, memos, and more.
              </p>
            </td>
          </tr>
          <!-- VIDEO CTA -->
          <tr>
            <td style="padding:0 40px 36px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0a140a;border:1px solid #2a4a2a;border-radius:6px;overflow:hidden;">
                <tr>
                  <td style="padding:0;">
                    <a href="https://ncokit.com/demo" style="display:block;text-decoration:none;">
                      <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:linear-gradient(160deg,#0f2a0f 0%,#1a3a1a 100%);height:220px;">
                        <tr>
                          <td align="center" valign="middle" style="height:220px;padding:20px;">
                            <div style="display:inline-block;width:68px;height:68px;background-color:#c9a227;border-radius:50%;text-align:center;line-height:68px;font-size:28px;margin-bottom:14px;">&#9654;</div>
                            <br>
                            <span style="font-size:18px;font-weight:700;color:#e8e4d4;letter-spacing:1px;">2-MINUTE FEATURE TOUR</span><br>
                            <span style="font-size:13px;color:#7dab7d;margin-top:6px;display:inline-block;">See all 7 tools in action &rarr;</span>
                          </td>
                        </tr>
                      </table>
                    </a>
                  </td>
                </tr>
                <tr>
                  <td style="padding:14px 20px;border-top:1px solid #1a3a1a;">
                    <span style="font-size:12px;color:#5a8a5a;">&#128241; &nbsp;Watch on your phone &mdash; formatted for mobile</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- DIVIDER -->
          <tr><td style="padding:0 40px 8px;"><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="border-top:1px solid #1a3a1a;">&nbsp;</td></tr></table></td></tr>
          <!-- WHAT'S IN THE KIT -->
          <tr><td style="padding:16px 40px 8px;"><h2 style="margin:0 0 24px;font-size:13px;font-weight:700;color:#7dab7d;letter-spacing:3px;text-transform:uppercase;">What's in the kit</h2></td></tr>
          <!-- DA 4856 -->
          <tr><td style="padding:0 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#128203; &nbsp;DA Form 4856 &mdash; Counseling Generator</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Fill in rough notes &mdash; AI rewrites them in proper Army regulatory language and generates a print-ready DA 4856. Works for initial, monthly, and event-driven counselings.</span></td></tr></table></td></tr>
          <!-- Soldier Roster -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#129510; &nbsp;Soldier Roster &mdash; Track Your Whole Squad</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">See every Soldier's counseling status &mdash; Current, Due, or Overdue &mdash; at a glance. Upload previous counselings to keep a complete record in one place. Hit <strong style="color:#e8e4d4;">&#10022; AI Scrub</strong> on any Soldier to instantly generate awards or NCOER bullets from their record.</span></td></tr></table></td></tr>
          <!-- NCOER Bullets -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#11088; &nbsp;NCOER Bullet Builder &mdash; AI-Powered</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Type a plain-language achievement. AI converts it into tight, impact-first NCOER bullets that meet Army writing standards &mdash; character-count compliant, no fluff.</span></td></tr></table></td></tr>
          <!-- Awards -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#127885; &nbsp;Awards Writer &mdash; AAM &middot; ARCOM &middot; MSM</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Draft complete award citations from bullet points. AI formats them to the correct standard for any award level &mdash; grounded in AR 600-8-22 and Army writing standards.</span></td></tr></table></td></tr>
          <!-- OER -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#128221; &nbsp;OER Bullet Builder</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Same AI-powered engine, built specifically for OER narratives. Proper formatting, proper language, ready to paste.</span></td></tr></table></td></tr>
          <!-- Memo -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#128196; &nbsp;Memo Generator &mdash; AR 25-50 Compliant</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Generate properly formatted Army memorandums in seconds. Fill in the key facts &mdash; AI handles the structure, format, and language.</span></td></tr></table></td></tr>
          <!-- ACFT Calculator -->
          <tr><td style="padding:4px 40px 6px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#127939; &nbsp;ACFT Calculator</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Score any ACFT event instantly. Enter raw scores across all six events and get a pass/fail result with point totals &mdash; calibrated by age and gender per Army standards.</span></td></tr></table></td></tr>
          <!-- Senior Rater -->
          <tr><td style="padding:4px 40px 24px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#0f2a0f;border-left:3px solid #c9a227;border-radius:0 4px 4px 0;"><tr><td style="padding:16px 18px;"><span style="font-size:13px;font-weight:700;color:#c9a227;text-transform:uppercase;letter-spacing:1px;">&#9889; &nbsp;Senior Rater Narrative Generator</span><br><span style="font-size:14px;color:#a8c8a8;line-height:1.6;display:block;margin-top:5px;">Build EES-ready Senior Rater narratives using the ESPN framework &mdash; Enumeration, School, Promotion, Next Level. Specify the Soldier's ranking and the AI produces a polished, differentiated narrative.</span></td></tr></table></td></tr>
          <!-- CTA -->
          <tr><td style="padding:4px 40px 36px;" align="center"><a href="https://ncokit.com" style="display:inline-block;background-color:#c9a227;color:#0a140a;font-size:17px;font-weight:900;text-decoration:none;padding:16px 48px;border-radius:4px;letter-spacing:1px;text-transform:uppercase;">Open NCO Kit &rarr;</a><br><span style="font-size:12px;color:#4a7a4a;display:block;margin-top:12px;">Free. No credit card. No catch.</span></td></tr>
          <!-- DIVIDER -->
          <tr><td style="padding:0 40px;"><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="border-top:1px solid #1a3a1a;">&nbsp;</td></tr></table></td></tr>
          <!-- TIPS -->
          <tr>
            <td style="padding:28px 40px 32px;">
              <h2 style="margin:0 0 16px;font-size:13px;font-weight:700;color:#7dab7d;letter-spacing:3px;text-transform:uppercase;">Quick tips to get started</h2>
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr><td style="padding:5px 0;font-size:14px;color:#a8c8a8;line-height:1.6;"><strong style="color:#c9a227;">1.</strong> &nbsp;Start with the <strong style="color:#e8e4d4;">Soldier Roster</strong> &mdash; add your squad and get a live counseling dashboard.</td></tr>
                <tr><td style="padding:5px 0;font-size:14px;color:#a8c8a8;line-height:1.6;"><strong style="color:#c9a227;">2.</strong> &nbsp;Hit <strong style="color:#e8e4d4;">&#10022; AI Scrub</strong> on any Soldier to generate bullets or an award citation instantly.</td></tr>
                <tr><td style="padding:5px 0;font-size:14px;color:#a8c8a8;line-height:1.6;"><strong style="color:#c9a227;">3.</strong> &nbsp;All documents are exportable. Generate a DA 4856, review it, and print &mdash; takes about 60 seconds.</td></tr>
                <tr><td style="padding:5px 0;font-size:14px;color:#a8c8a8;line-height:1.6;"><strong style="color:#c9a227;">4.</strong> &nbsp;Upload previous counselings directly into a Soldier's record to keep everything in one place.</td></tr>
                <tr><td style="padding:5px 0;font-size:14px;color:#a8c8a8;line-height:1.6;"><strong style="color:#c9a227;">5.</strong> &nbsp;The site works on your phone. Add it to your home screen for quick access in the field.</td></tr>
              </table>
            </td>
          </tr>
          <!-- FOOTER -->
          <tr>
            <td style="background-color:#080f08;border-top:3px solid #c9a227;padding:28px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="text-align:center;">
                    <span style="font-size:20px;font-weight:900;color:#c9a227;letter-spacing:2px;text-transform:uppercase;">NCO KIT</span><br>
                    <span style="font-size:12px;color:#4a7a4a;letter-spacing:2px;text-transform:uppercase;display:block;margin-top:4px;">Army Leader's Toolkit</span>
                    <br>
                    <a href="https://ncokit.com" style="font-size:13px;color:#7dab7d;text-decoration:none;">ncokit.com</a>
                    &nbsp;|&nbsp;
                    <a href="https://ncokit.com/unsubscribe" style="font-size:13px;color:#4a7a4a;text-decoration:none;">Unsubscribe</a>
                    <br><br>
                    <span style="font-size:11px;color:#2a4a2a;line-height:1.6;">You're receiving this because you created an account at ncokit.com.<br>This is a transactional email related to your account.</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
  await sendEmail(email, "You're verified — welcome to NCO Kit", html);
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => res.json({ status: 'online' }));

// SEO
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nAllow: /\nSitemap: https://ncokit.com/sitemap.xml`);
});

app.get('/sitemap.xml', (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://ncokit.com</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://ncokit.com/#bullets</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://ncokit.com/#counseling</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://ncokit.com/#awards</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://ncokit.com/#acft</loc>
    <lastmod>${today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://ncokit.com/privacy</loc>
    <lastmod>${today}</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.3</priority>
  </url>
</urlset>`);
});

// ── APPLY REFERRAL CODE (post-signup) ───────────────────────────────────────
// Lets a free user who signed up without a referral code apply one later.
// The 50% discount fires automatically at Stripe checkout if referred_by is set.
app.post('/api/auth/apply-referral', authLimiter, async (req, res) => {
  try {
    const user = await getUserFromSession(req);
    if (!user) return res.status(401).json({ error: 'Sign in to apply a referral code' });
    if (user.referred_by) return res.status(400).json({ error: 'A referral code is already applied to your account' });
    if (user.plan === 'premium') return res.status(400).json({ error: 'You are already on Premium — no discount needed!' });
    if (user.stripe_customer_id) return res.status(400).json({ error: 'A referral code can only be applied before your first upgrade' });

    const { code } = req.body;
    if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Invalid referral code' });
    const cleanCode = code.trim().toUpperCase();

    // Make sure the code exists and doesn't belong to the user themselves
    const referrer = await pool.query(
      'SELECT id FROM users WHERE referral_code = $1',
      [cleanCode]
    );
    if (referrer.rows.length === 0) return res.status(404).json({ error: 'Referral code not found — double-check and try again' });
    if (referrer.rows[0].id === user.id) return res.status(400).json({ error: 'You cannot use your own referral code' });

    // Apply the code
    await pool.query(
      'UPDATE users SET referred_by = $1 WHERE id = $2',
      [cleanCode, user.id]
    );

    res.json({ success: true, message: 'Referral code applied — your 50% discount will be applied at checkout' });
  } catch (err) {
    console.error('apply-referral error:', err);
    res.status(500).json({ error: 'Something went wrong — try again' });
  }
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
      'SELECT id, email FROM users WHERE verification_token = $1 AND verification_expires > NOW() AND verified = FALSE',
      [token]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired verification link' });
    await pool.query('UPDATE users SET verified = TRUE, verification_token = NULL, verification_expires = NULL WHERE id = $1', [result.rows[0].id]);
    // Add to Resend audience for marketing emails (non-blocking)
    fetch(`https://api.resend.com/audiences/${process.env.RESEND_AUDIENCE_ID}/contacts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({ email: result.rows[0].email, unsubscribed: false })
    }).catch(err => console.error('Resend add contact failed:', err.message));
    // Send welcome email (non-blocking — don't let email failure break verification)
    sendWelcomeEmail(result.rows[0].email).catch(err =>
      console.error('Welcome email failed:', err.message)
    );
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
app.post('/api/generate-memo', aiLimiter, checkUsageLimit(1), async (req, res) => {
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
app.post('/api/validate-oer-category', aiLimiter, checkUsageLimit(1), async (req, res) => {
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
      let parsed;
      try {
        parsed = await pdfParse(buffer);
      } catch (pdfErr) {
        console.error('PDF parse error:', pdfErr.message);
        if (pdfErr.message?.includes('bad XRef') || pdfErr.message?.includes('Crypt')) {
          return res.status(422).json({
            error: 'This PDF is encrypted or password-protected. Open it, print it to a new PDF, then re-upload.'
          });
        }
        return res.status(422).json({
          error: 'Could not read this PDF. Try re-saving it as a standard PDF and uploading again.'
        });
      }
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

// ═══════════════════════════════════════════════════════════════════
// GA4 HELPERS — uses GOOGLE_SA_JSON env var (service account JSON)
// GA4 Property ID: 529138485
// ═══════════════════════════════════════════════════════════════════
async function getGAToken() {
  try {
    const sa = JSON.parse(process.env.GOOGLE_SA_JSON || 'null');
    if (!sa || !sa.private_key) return null;
    const now = Math.floor(Date.now() / 1000);
    const hdr = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const pay = Buffer.from(JSON.stringify({
      iss: sa.client_email,
      scope: 'https://www.googleapis.com/auth/analytics.readonly',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600, iat: now
    })).toString('base64url');
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(`${hdr}.${pay}`);
    const sig = signer.sign(sa.private_key, 'base64url');
    const jwt = `${hdr}.${pay}.${sig}`;
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
    });
    const d = await r.json();
    return d.access_token || null;
  } catch(e) { console.error('GA token err:', e.message); return null; }
}

async function ga4Report(token, metrics, dimensions, startDate) {
  const r = await fetch('https://analyticsdata.googleapis.com/v1beta/properties/529138485:runReport', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({
      dateRanges: [{ startDate, endDate: 'today' }],
      metrics: metrics.map(m => ({ name: m })),
      ...(dimensions ? { dimensions: dimensions.map(d => ({ name: d })), orderBys: [{ metric: { metricName: metrics[0] }, desc: true }], limit: 6 } : {})
    })
  });
  return r.json();
}

// ═══════════════════════════════════════════════════════════════════
// WEEKLY REPORT — Monday rollup email via Resend
// Trigger: POST /api/admin/weekly-report with x-report-secret header
// ═══════════════════════════════════════════════════════════════════
app.post('/api/admin/weekly-report', async (req, res) => {
  const secret = req.headers['x-report-secret'] || req.query.secret;
  if (!secret || secret !== process.env.WEEKLY_REPORT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const now = new Date();
    const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const weekAgoISO = weekAgo.toISOString();
    const weekAgoUnix = Math.floor(weekAgo.getTime() / 1000);

    // ── DB Stats ─────────────────────────────────────────────────────
    const [totalU, newU, premU, newPremU, totC, newC, totB, newB, totA, newA, totO, newO, newVerifiedU, unverifiedU] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM users WHERE created_at >= $1', [weekAgoISO]),
      pool.query("SELECT COUNT(*) FROM users WHERE plan = 'premium'"),
      pool.query("SELECT COUNT(*) FROM users WHERE plan = 'premium' AND updated_at >= $1", [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM saved_counselings'),
      pool.query('SELECT COUNT(*) FROM saved_counselings WHERE created_at >= $1', [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM saved_bullets'),
      pool.query('SELECT COUNT(*) FROM saved_bullets WHERE created_at >= $1', [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM saved_awards'),
      pool.query('SELECT COUNT(*) FROM saved_awards WHERE created_at >= $1', [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM saved_oer_bullets'),
      pool.query('SELECT COUNT(*) FROM saved_oer_bullets WHERE created_at >= $1', [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM users WHERE verified = TRUE AND created_at >= $1', [weekAgoISO]),
      pool.query('SELECT COUNT(*) FROM users WHERE verified = FALSE'),
    ]);
    const db = {
      totalUsers:     parseInt(totalU.rows[0].count),
      newUsers:       parseInt(newU.rows[0].count),
      premiumUsers:   parseInt(premU.rows[0].count),
      newPremium:     parseInt(newPremU.rows[0].count),
      totCounselings: parseInt(totC.rows[0].count),
      newCounselings: parseInt(newC.rows[0].count),
      totBullets:     parseInt(totB.rows[0].count),
      newBullets:     parseInt(newB.rows[0].count),
      totAwards:      parseInt(totA.rows[0].count),
      newAwards:      parseInt(newA.rows[0].count),
      totOER:         parseInt(totO.rows[0].count),
      newOER:         parseInt(newO.rows[0].count),
      newVerified:    parseInt(newVerifiedU.rows[0].count),
      unverified:     parseInt(unverifiedU.rows[0].count),
    };

    // ── Stripe Stats ─────────────────────────────────────────────────
    let s = { revenue: '0.00', newCustomers: 0, activeSubs: 0, newSubs: 0 };
    try {
      const [charges, newCusts, activeSubs, newSubs] = await Promise.all([
        stripe.charges.list({ created: { gte: weekAgoUnix }, limit: 100 }),
        stripe.customers.list({ created: { gte: weekAgoUnix }, limit: 100 }),
        stripe.subscriptions.list({ status: 'active', limit: 100 }),
        stripe.subscriptions.list({ created: { gte: weekAgoUnix }, limit: 100 }),
      ]);
      s.revenue      = (charges.data.filter(c => c.paid && !c.refunded).reduce((sum, c) => sum + c.amount, 0) / 100).toFixed(2);
      s.newCustomers = newCusts.data.length;
      s.activeSubs   = activeSubs.data.length;
      s.newSubs      = newSubs.data.length;
    } catch(e) { console.error('Stripe report err:', e.message); }

    // ── GA4 Traffic Stats ─────────────────────────────────────────────
    let ga = { sessions: 'N/A', newUsers: 'N/A', returningUsers: 'N/A', avgDuration: 'N/A', bounceRate: 'N/A', topSources: [], topPages: [], enabled: false };
    try {
      const gaToken = await getGAToken();
      if (gaToken) {
        const [overview, sources, pages] = await Promise.all([
          ga4Report(gaToken, ['sessions','newUsers','activeUsers','averageSessionDuration','bounceRate'], null, '7daysAgo'),
          ga4Report(gaToken, ['sessions'], ['sessionDefaultChannelGrouping'], '7daysAgo'),
          ga4Report(gaToken, ['screenPageViews'], ['pagePath'], '7daysAgo'),
        ]);
        if (overview.rows && overview.rows[0]) {
          const v = overview.rows[0].metricValues;
          const dur = parseFloat(v[3].value);
          const sessCount   = parseInt(v[0].value);
          const newCount     = parseInt(v[1].value);
          const activeCount   = parseInt(v[2].value);
          ga.sessions       = sessCount.toLocaleString();
          ga.newUsers       = newCount.toLocaleString();
          ga.returningUsers = Math.max(0, activeCount - newCount).toLocaleString();
          ga.avgDuration    = Math.floor(dur/60) + 'm ' + String(Math.floor(dur%60)).padStart(2,'0') + 's';
          ga.bounceRate     = (parseFloat(v[4].value)*100).toFixed(1) + '%';
          ga.enabled     = true;
        }
        if (sources.rows) {
          ga.topSources = sources.rows.slice(0,5).map(r => ({
            source: r.dimensionValues[0].value, sessions: parseInt(r.metricValues[0].value).toLocaleString()
          }));
        }
        if (pages.rows) {
          ga.topPages = pages.rows.slice(0,5).map(r => ({
            page: r.dimensionValues[0].value, views: parseInt(r.metricValues[0].value).toLocaleString()
          }));
        }
      }
    } catch(e) { console.error('GA4 report err:', e.message); }

    // ── Date Range Label ─────────────────────────────────────────────
    const fmt = d => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const range = fmt(weekAgo) + ' \u2013 ' + now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

    // ── GA4 Traffic HTML section ─────────────────────────────────────
    const gaSection = ga.enabled ? `
  <div class="sec">
    <div class="sec-ttl">&#127760; Website Traffic &mdash; GA4</div>
    <div class="grid" style="margin-bottom:10px">
      <div class="stat"><div class="n">${ga.sessions}</div><div class="lbl">Sessions</div></div>
      <div class="stat"><div class="n">${ga.newUsers}</div><div class="lbl">New Visitors</div></div>
    </div>
    <div class="grid" style="margin-bottom:10px">
      <div class="stat"><div class="n">${ga.returningUsers}</div><div class="lbl">Returning Visitors</div></div>
    </div>
    <div class="grid">
      <div class="stat"><div class="n">${ga.avgDuration}</div><div class="lbl">Avg Session Duration</div></div>
      <div class="stat"><div class="n">${ga.bounceRate}</div><div class="lbl">Bounce Rate</div></div>
    </div>
    ${ga.topSources.length ? `<table style="width:100%;border-collapse:collapse;margin-top:14px"><tr><th style="text-align:left;font-size:10px;letter-spacing:2px;color:#C8B48A;font-family:monospace;padding:6px 8px;border-bottom:1px solid #3d5440">SOURCE / MEDIUM</th><th style="text-align:right;font-size:10px;letter-spacing:2px;color:#C8B48A;font-family:monospace;padding:6px 8px;border-bottom:1px solid #3d5440">SESSIONS</th></tr>${ga.topSources.map(s=>`<tr><td style="font-size:12px;color:#F4F1EA;padding:7px 8px;border-bottom:1px solid #2B3A2E;font-family:monospace">${s.source}</td><td style="font-size:12px;color:#C8B48A;text-align:right;padding:7px 8px;border-bottom:1px solid #2B3A2E;font-family:monospace">${s.sessions}</td></tr>`).join('')}</table>` : ''}
    ${ga.topPages.length ? `<table style="width:100%;border-collapse:collapse;margin-top:10px"><tr><th style="text-align:left;font-size:10px;letter-spacing:2px;color:#C8B48A;font-family:monospace;padding:6px 8px;border-bottom:1px solid #3d5440">TOP PAGES</th><th style="text-align:right;font-size:10px;letter-spacing:2px;color:#C8B48A;font-family:monospace;padding:6px 8px;border-bottom:1px solid #3d5440">VIEWS</th></tr>${ga.topPages.map(p=>`<tr><td style="font-size:12px;color:#F4F1EA;padding:7px 8px;border-bottom:1px solid #2B3A2E;font-family:monospace">${p.page}</td><td style="font-size:12px;color:#C8B48A;text-align:right;padding:7px 8px;border-bottom:1px solid #2B3A2E;font-family:monospace">${p.views}</td></tr>`).join('')}</table>` : ''}
  </div>` : `
  <div class="sec">
    <div class="sec-ttl">&#127760; Website Traffic</div>
    <p style="font-size:11px;color:#a08e65;font-family:monospace;margin:0">GA4 not yet connected &mdash; add GOOGLE_SA_JSON to Render env to enable</p>
    <a class="cta" href="https://analytics.google.com/analytics/web/#/p529138485/reports/reportinghub" style="margin-top:12px;display:inline-block">View GA4 Dashboard</a>
  </div>`;

    // ── HTML Email ───────────────────────────────────────────────────
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
body{font-family:Arial,sans-serif;background:#0d0f0d;margin:0;padding:20px}
.wrap{max-width:620px;margin:0 auto;background:#1a2419;border:1px solid #3d5440}
.hdr{background:#2B3A2E;border-bottom:3px solid #C8B48A;padding:28px 32px}
.hdr h1{font-size:20px;letter-spacing:4px;text-transform:uppercase;color:#C8B48A;margin:0 0 4px}
.hdr p{font-size:11px;color:#a08e65;letter-spacing:2px;margin:0;font-family:monospace}
.sec{padding:22px 32px;border-bottom:1px solid #3d5440}
.sec-ttl{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#C8B48A;font-family:monospace;margin-bottom:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.stat{background:#0d0f0d;border:1px solid #3d5440;border-bottom:2px solid #C8B48A;padding:14px 16px}
.n{font-size:26px;color:#C8B48A;font-weight:bold;font-family:monospace;line-height:1}
.lbl{font-size:10px;color:#a08e65;letter-spacing:1px;text-transform:uppercase;font-family:monospace;margin-top:4px}
.new{font-size:10px;color:#4CAF50;font-family:monospace;margin-top:3px}
.cta{display:inline-block;background:#C8B48A;color:#1a2419;font-size:11px;letter-spacing:2px;text-transform:uppercase;text-decoration:none;padding:10px 18px;font-family:monospace;font-weight:bold;margin:4px}
.ftr{padding:18px 32px;text-align:center;font-size:10px;color:#a08e65;font-family:monospace;letter-spacing:1px}
</style></head><body>
<div class="wrap">
  <div class="hdr"><h1>&#11088; NCO Kit Weekly Report</h1><p>${range}</p></div>

  <div class="sec">
    <div class="sec-ttl">&#128202; User Growth</div>
    <div class="grid">
      <div class="stat"><div class="n">${db.totalUsers}</div><div class="lbl">Total Users</div><div class="new">+${db.newUsers} signed up this week</div></div>
      <div class="stat"><div class="n">${db.premiumUsers}</div><div class="lbl">Premium Subscribers</div><div class="new">+${db.newPremium} upgraded</div></div>
    </div>
    <div class="grid" style="margin-top:10px">
      <div class="stat"><div class="n">${db.newVerified}</div><div class="lbl">Verified This Week</div><div class="new" style="color:#C8B48A">${db.unverified} awaiting verification</div></div>
    </div>
  </div>

  <div class="sec">
    <div class="sec-ttl">&#128176; Revenue &mdash; Stripe</div>
    <div class="grid">
      <div class="stat"><div class="n">$${s.revenue}</div><div class="lbl">Revenue This Week</div><div class="new">${s.newCustomers} new customers</div></div>
      <div class="stat"><div class="n">${s.activeSubs}</div><div class="lbl">Active Subscriptions</div><div class="new">+${s.newSubs} new this week</div></div>
    </div>
  </div>

  ${gaSection}

  <div class="sec">
    <div class="sec-ttl">&#128295; Tool Usage This Week</div>
    <div class="grid3">
      <div class="stat"><div class="n">${db.newCounselings}</div><div class="lbl">Counselings</div><div class="new">${db.totCounselings} all-time</div></div>
      <div class="stat"><div class="n">${db.newBullets}</div><div class="lbl">NCOER Bullets</div><div class="new">${db.totBullets} all-time</div></div>
      <div class="stat"><div class="n">${db.newAwards}</div><div class="lbl">Awards</div><div class="new">${db.totAwards} all-time</div></div>
    </div>
    <div class="grid" style="margin-top:10px">
      <div class="stat"><div class="n">${db.newOER}</div><div class="lbl">OER Bullets</div><div class="new">${db.totOER} all-time</div></div>
    </div>
  </div>

  <div class="sec">
    <div class="sec-ttl">&#128279; Dashboards</div>
    <a class="cta" href="https://analytics.google.com/analytics/web/#/p529138485/reports/reportinghub">GA4 Analytics</a>
    <a class="cta" href="https://dashboard.stripe.com/dashboard">Stripe Dashboard</a>
    <a class="cta" href="https://ncokit.com">NCO Kit Live</a>
  </div>

  <div class="ftr">NCO Kit &mdash; Automated weekly report &mdash; ncokit.com</div>
</div>
</body></html>`;

    // ── Send via Resend ──────────────────────────────────────────────
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.RESEND_API_KEY}` },
      body: JSON.stringify({
        from: 'NCO Kit Reports <noreply@ncokit.com>',
        to: ['brighamwilsonjr@gmail.com'],
        subject: `NCO Kit Weekly Report \u2014 ${range}`,
        html
      })
    });
    const emailData = await r.json();
    res.json({ ok: true, db, stripe: s, ga, emailId: emailData.id });
  } catch (err) {
    console.error('Weekly report error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── ADMIN: USAGE STATS ────────────────────────────────────────────────────────
app.get('/api/admin/usage-stats', async (req, res) => {
  const secret = req.headers['x-report-secret'];
  if (secret !== process.env.WEEKLY_REPORT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    // Users who have hit or are near the 10/month limit
    const atLimit = await pool.query(`
      SELECT email, plan, bullets_used_this_month, bullets_reset_date, verified, created_at
      FROM users
      WHERE plan = 'free' AND bullets_used_this_month >= 10
      ORDER BY bullets_used_this_month DESC
    `);
    const nearLimit = await pool.query(`
      SELECT email, plan, bullets_used_this_month, bullets_reset_date, verified, created_at
      FROM users
      WHERE plan = 'free' AND bullets_used_this_month >= 7 AND bullets_used_this_month < 10
      ORDER BY bullets_used_this_month DESC
    `);
    const allFree = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE plan = 'free') AS total_free,
        COUNT(*) FILTER (WHERE plan = 'free' AND bullets_used_this_month >= 10) AS at_limit,
        COUNT(*) FILTER (WHERE plan = 'free' AND bullets_used_this_month >= 7 AND bullets_used_this_month < 10) AS near_limit,
        COUNT(*) FILTER (WHERE plan = 'free' AND bullets_used_this_month > 0 AND bullets_used_this_month < 7) AS active_under_limit,
        COUNT(*) FILTER (WHERE plan = 'free' AND bullets_used_this_month = 0) AS not_used,
        COUNT(*) FILTER (WHERE plan = 'premium') AS total_premium
      FROM users
    `);
    // Inactive users: signed up > 72 hours ago, never used the tool
    const cutoff = new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString();
    const inactive = await pool.query(`
      SELECT email, created_at
      FROM users
      WHERE plan = 'free' AND bullets_used_this_month = 0 AND created_at < $1
      ORDER BY created_at DESC
    `, [cutoff]);

    res.json({
      summary: allFree.rows[0],
      inactiveCount: inactive.rows.length,
      inactiveUsers: inactive.rows,
      atLimit: atLimit.rows,
      nearLimit: nearLimit.rows
    });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});


// ── ADMIN: RE-ENGAGEMENT BATCH SEND ──────────────────────────────────────────
// Sends 48 emails per batch to inactive free users (signed up >72h ago, 0 usage)
// Call with { batch: 0 } for first 48, { batch: 1 } for next 48, { batch: 2 } for last batch
app.post('/api/admin/send-reengagement', async (req, res) => {
  const secret = req.headers['x-report-secret'];
  if (secret !== process.env.WEEKLY_REPORT_SECRET) return res.status(401).json({ error: 'Unauthorized' });

  const batchSize = 48;
  const batchNum  = parseInt(req.body.batch ?? 0);
  const offset    = batchNum * batchSize;
  const cutoff    = new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString();

  try {
    const result = await pool.query(`
      SELECT email, referral_code FROM users
      WHERE plan = 'free' AND bullets_used_this_month = 0 AND created_at < $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `, [cutoff, batchSize, offset]);

    const recipients = result.rows.map(r => ({ email: r.email, refCode: r.referral_code || '' }));
    if (recipients.length === 0) return res.json({ sent: 0, message: 'No recipients in this batch' });

    const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NCO Kit</title>
</head>
<body style="margin:0;padding:0;background:#1a1a1a;font-family:'Georgia',serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1a1a;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr><td style="background:#2a2419;border-top:4px solid #a08e65;border-radius:8px 8px 0 0;padding:28px 40px;">
          <p style="margin:0;font-size:22px;font-weight:bold;color:#a08e65;letter-spacing:2px;text-transform:uppercase;">NCO Kit</p>
          <p style="margin:4px 0 0;font-size:11px;color:#6b5e45;letter-spacing:1px;text-transform:uppercase;">Army Leader's Toolkit</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background:#242018;padding:36px 40px;">
          <p style="margin:0 0 20px;font-size:15px;line-height:1.7;color:#c8b88a;">
            You set up an NCO Kit account a little while back but haven't had a chance to use it yet.
            No problem — we know the battle rhythm doesn't slow down.
          </p>
          <p style="margin:0 0 20px;font-size:15px;line-height:1.7;color:#c8b88a;">
            When you get a free five minutes, here's the fastest way to see what it can do:
            pick a category, type in what your Soldier did, and get three ready-to-use NCOER bullets
            back in seconds — formatted to Army writing standards, calibrated to their MOS.
          </p>
          <p style="margin:0 0 32px;font-size:15px;line-height:1.7;color:#c8b88a;">
            NCO Kit also handles DA 4856 counselings, awards write-ups, OER bullets, and AFT scores.
            Everything you hate typing, done in one place.
          </p>

          <!-- CTA Button -->
          <table cellpadding="0" cellspacing="0"><tr><td>
            <a href="${refLink}" style="display:inline-block;background:#a08e65;color:#1a1a1a;font-family:'Georgia',serif;font-size:15px;font-weight:bold;letter-spacing:1px;text-decoration:none;padding:14px 36px;border-radius:4px;text-transform:uppercase;">
              Open NCO Kit →
            </a>
          </td></tr></table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background:#1e1b14;border-top:1px solid #3a3020;border-radius:0 0 8px 8px;padding:20px 40px;">
          <p style="margin:0;font-size:12px;color:#6b5e45;line-height:1.6;">
            Built by NCOs, for NCOs.<br>
            — Henry @ NCO Kit<br><br>
            <a href="https://ncokit.com/privacy" style="color:#6b5e45;">Privacy Policy</a> &nbsp;|&nbsp;
            You're receiving this because you created an account at ncokit.com.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

    let sent = 0;
    const errors = [];
    for (const { email, refCode } of recipients) {
      try {
        const refLink = refCode ? `https://ncokit.com?ref=${refCode}` : 'https://ncokit.com';
        const personalizedHtml = htmlBody.replace('${refLink}', refLink);
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'Henry @ NCO Kit <noreply@ncokit.com>',
            to: email,
            subject: "You've got an NCO Kit account — here's where to start",
            html: personalizedHtml
          })
        });
        sent++;
      } catch(e) { errors.push({ email, error: e.message }); }
    }

    res.json({ batch: batchNum, sent, total: recipients.length, errors });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});


// ── ADMIN: USER LOOKUP ────────────────────────────────────────────────────────
app.get('/api/admin/user-lookup', async (req, res) => {
  const secret = req.headers['x-report-secret'];
  if (secret !== process.env.WEEKLY_REPORT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: 'email query param required' });
  try {
    const result = await pool.query(
      'SELECT id, email, plan, verified, bullets_used_this_month, bullets_reset_date, created_at FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch(err) {
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
