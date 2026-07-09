require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');
const { Resend } = require('resend');
const { sql } = require('@vercel/postgres');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, initializeDatabase } = require('./db/client');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.ANTHROPIC_API_KEY) {
  console.warn('WARNING: ANTHROPIC_API_KEY is not set. AI analysis will fail.');
}
if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('WARNING: STRIPE_SECRET_KEY is not set. Billing routes will fail.');
}
if (!process.env.RESEND_API_KEY) {
  console.warn('WARNING: RESEND_API_KEY is not set. Email sending will fail.');
}

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');
const resend = new Resend(process.env.RESEND_API_KEY || 'dummy_key');

// ═══════════════════════════════════════════════════════════════════════════════
// 🔒 SECURITY MIDDLEWARE - Applied to all requests
// ═══════════════════════════════════════════════════════════════════════════════

// 1. Security Headers - Protect against common attacks
app.use((req, res, next) => {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Enable XSS protection in older browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Force HTTPS (only in production)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // Content Security Policy - Allow trusted external resources
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://cdnjs.cloudflare.com");

  // Referrer Policy - Limit referrer information
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy - Restrict sensitive APIs
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  next();
});

// 2. CORS Protection - Only allow your own domain
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  process.env.FRONTEND_URL,
  'https://finread.app',
  'https://www.finread.app'
].filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// 3. Request Size Limits - Prevent DOS via large payloads
// NOTE: express.json() and urlencoded() are defined later (line 313+)
// AFTER the Stripe webhook route to avoid parsing the webhook body

// 4. Global Rate Limiting - Prevent abuse
const globalRateLimits = new Map();
const GLOBAL_RATE_LIMIT = 1000; // requests
const GLOBAL_RATE_WINDOW = 60000; // per minute

function checkGlobalRateLimit(ip) {
  const now = Date.now();
  const limit = globalRateLimits.get(ip) || { count: 0, resetTime: now + GLOBAL_RATE_WINDOW };

  if (now > limit.resetTime) {
    limit.count = 0;
    limit.resetTime = now + GLOBAL_RATE_WINDOW;
  }

  limit.count++;
  globalRateLimits.set(ip, limit);

  return limit.count <= GLOBAL_RATE_LIMIT;
}

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkGlobalRateLimit(ip)) {
    console.warn(`[SECURITY] Rate limit exceeded for IP: ${ip}`);
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }
  next();
});

// 5. Input Sanitization Helper - Prevent XSS
global.sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

// 6. Security Logging Middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const statusCode = res.statusCode;

    // Log security-relevant status codes
    if (statusCode >= 400) {
      console.log(`[SECURITY-LOG] ${req.method} ${req.path} - Status: ${statusCode} - IP: ${req.ip} - Duration: ${duration}ms`);
    }
  });
  next();
});

// Analysis cache to avoid re-analyzing the same filing
// Key: `${ticker}:${accessionNumber}:${formType}`, Value: { result, timestamp }
// Cache expires after 24 hours
const analysisCache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// ── PEER GROUPS (Phase 5, Task 7) ──────────────────────────────────────────
// Map companies to their peer groups for benchmarking analysis
const peerGroups = {
  'MSFT': ['AAPL', 'GOOG', 'META', 'NVDA', 'AMZN'],
  'AAPL': ['MSFT', 'GOOG', 'META', 'NVDA'],
  'GOOG': ['MSFT', 'AAPL', 'META', 'AMZN'],
  'META': ['MSFT', 'AAPL', 'GOOG', 'SNAP'],
  'NVDA': ['AMD', 'INTC', 'QCOM', 'MSFT'],
  'AMZN': ['WMT', 'COST', 'TGT', 'HD'],
  'TSLA': ['F', 'GM', 'BMW', 'TOYOTA'],
  'JNJ': ['PFE', 'MRK', 'ABBV', 'LLY'],
  'V': ['MA', 'AXP', 'DIS'],
  'JPM': ['BAC', 'WFC', 'GS', 'MS'],
  'DEFAULT': ['MSFT', 'AAPL', 'GOOG', 'META', 'AMZN']  // Fallback peers
};

// Cache for peer metrics (ticker -> metrics object)
const peerMetricsCache = new Map();
const PEER_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// ── HISTORICAL METRICS TRACKING (Phase 5, Task 8) ────────────────────────────

// Helper: Store metrics history when analysis is completed
async function storeMetricsHistory(ticker, filingDate, formType, metrics, ratios, healthScore, filingUrl) {
  try {
    let history = await readJSON(METRICS_HISTORY_FILE).catch(() => []);

    // Check if this filing is already stored
    const existingIdx = history.findIndex(h =>
      h.ticker === ticker && h.filingDate === filingDate && h.formType === formType
    );

    const record = {
      ticker,
      filingDate,
      formType,
      // Raw metrics
      revenue: metrics.revenue,
      grossProfit: metrics.grossProfit,
      operatingIncome: metrics.operatingIncome,
      netIncome: metrics.netIncome,
      operatingCashFlow: metrics.operatingCashFlow,
      capex: metrics.capex,
      freeCashFlow: metrics.freeCashFlow,
      totalAssets: metrics.totalAssets,
      currentAssets: metrics.currentAssets,
      liabilities: metrics.liabilities,
      currentLiabilities: metrics.currentLiabilities,
      // Calculated ratios (13 metrics)
      roa: ratios.roa,
      roic: ratios.roic,
      operatingExpenseRatio: ratios.operatingExpenseRatio,
      fcfConversionRate: ratios.fcfConversionRate,
      fcfYield: ratios.fcfYield,
      capexIntensity: ratios.capexIntensity,
      accrualsRatio: ratios.accrualsRatio,
      workingCapitalPercent: ratios.workingCapitalPercent,
      netDebtToFCF: ratios.netDebtToFCF,
      daToRevenue: ratios.daToRevenue,
      returnOnCapex: ratios.returnOnCapex,
      effectiveTaxRate: ratios.effectiveTaxRate,
      grossMargin: ratios.grossMargin,
      // Health score
      healthScore: healthScore?.rating || 0,
      filingUrl,
      storedAt: new Date().toISOString()
    };

    if (existingIdx >= 0) {
      history[existingIdx] = record;
    } else {
      history.push(record);
    }

    await writeJSON(METRICS_HISTORY_FILE, history);
    console.log(`[metrics-history] Stored metrics for ${ticker} ${filingDate}`);

    // Calculate and store trends
    await calculateAndStoreTrends(ticker, formType);
  } catch (err) {
    console.error('[metrics-history] Error storing metrics:', err);
  }
}

// Helper: Calculate trends by comparing current to previous metric
async function calculateAndStoreTrends(ticker, formType) {
  try {
    let history = await readJSON(METRICS_HISTORY_FILE).catch(() => []);
    const companyHistory = history.filter(h => h.ticker === ticker && h.formType === formType)
      .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate));

    if (companyHistory.length < 2) return; // Need at least 2 data points

    const current = companyHistory[0];
    const previous = companyHistory[1];

    let trends = await readJSON(TRENDS_FILE).catch(() => []);

    const metricsToTrack = ['roa', 'roic', 'fcfConversionRate', 'fcfYield', 'capexIntensity'];

    for (const metric of metricsToTrack) {
      const currentVal = current[metric];
      const previousVal = previous[metric];

      if (currentVal === undefined || previousVal === undefined) continue;

      const change = currentVal - previousVal;
      const changePct = previousVal !== 0 ? (change / Math.abs(previousVal)) * 100 : 0;

      // Determine trend direction based on metric type
      let trend = 'stable';
      if (Math.abs(changePct) > 2) {
        const positiveMetrics = ['roa', 'roic', 'fcfYield'];
        const negativeMetrics = ['capexIntensity', 'netDebtToFCF'];

        if (positiveMetrics.includes(metric)) {
          trend = change > 0 ? 'improving' : 'declining';
        } else if (negativeMetrics.includes(metric)) {
          trend = change < 0 ? 'improving' : 'declining';
        }
      }

      const trendRecord = {
        ticker,
        metric,
        periodType: formType === '10-Q' ? 'quarterly' : 'annual',
        currentValue: currentVal,
        previousValue: previousVal,
        changeAmount: change,
        changePct: changePct,
        trendStatus: trend,
        calculatedAt: new Date().toISOString()
      };

      // Find and update or add new trend
      const existingIdx = trends.findIndex(t =>
        t.ticker === ticker && t.metric === metric && t.periodType === trendRecord.periodType
      );

      if (existingIdx >= 0) {
        trends[existingIdx] = trendRecord;
      } else {
        trends.push(trendRecord);
      }
    }

    await writeJSON(TRENDS_FILE, trends);
    console.log(`[metrics-history] Calculated trends for ${ticker}`);
  } catch (err) {
    console.error('[metrics-history] Error calculating trends:', err);
  }
}

// Stripe webhook needs the raw, unsigned request body to verify its signature —
// must be registered before the global express.json() below, so this exact
// route bypasses JSON parsing while everything else still gets it.
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'finread.html'));
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Email verification page
app.get('/verify-email', (req, res) => {
  res.sendFile(path.join(__dirname, 'verify-email.html'));
});

// Password reset page
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// Forgot password page
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

// Contact page
app.get('/contact', (req, res) => {
  res.sendFile(path.join(__dirname, 'contact.html'));
});

// Account page
app.get('/account', (req, res) => {
  res.sendFile(path.join(__dirname, 'account.html'));
});

// Privacy Policy
app.get('/privacy-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy-policy.html'));
});

// Terms of Service
app.get('/terms-of-service', (req, res) => {
  res.sendFile(path.join(__dirname, 'terms-of-service.html'));
});

// ── DATA LAYER ────────────────────────────────────────────────────────────────

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const FLAGS_FILE = path.join(DATA_DIR, 'flags.json');
const ANNOTATIONS_FILE = path.join(DATA_DIR, 'annotations.json');
const METRICS_HISTORY_FILE = path.join(DATA_DIR, 'metrics_history.json');
const TRENDS_FILE = path.join(DATA_DIR, 'trends.json');
const WATCHLISTS_FILE = path.join(DATA_DIR, 'watchlists.json');
const SHARES_FILE = path.join(DATA_DIR, 'shares.json');
const BATCHES_FILE = path.join(DATA_DIR, 'batches.json');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
const ALERT_HISTORY_FILE = path.join(DATA_DIR, 'alert_history.json');
const XBRL_CACHE_FILE = path.join(DATA_DIR, 'xbrl_cache.json');
const FINANCIAL_METRICS_FILE = path.join(DATA_DIR, 'financial_metrics.json');
const TRENDS_JOBS_FILE = path.join(DATA_DIR, 'trends_jobs.json');

async function initDataDir() {
  if (!fsSync.existsSync(DATA_DIR)) await fs.mkdir(DATA_DIR, { recursive: true });
  if (!fsSync.existsSync(USERS_FILE)) await fs.writeFile(USERS_FILE, '[]');
  if (!fsSync.existsSync(REPORTS_FILE)) await fs.writeFile(REPORTS_FILE, '[]');
  if (!fsSync.existsSync(FLAGS_FILE)) await fs.writeFile(FLAGS_FILE, '[]');
  if (!fsSync.existsSync(ANNOTATIONS_FILE)) await fs.writeFile(ANNOTATIONS_FILE, '[]');
  if (!fsSync.existsSync(WATCHLISTS_FILE)) await fs.writeFile(WATCHLISTS_FILE, '[]');
  if (!fsSync.existsSync(SHARES_FILE)) await fs.writeFile(SHARES_FILE, '[]');
  if (!fsSync.existsSync(BATCHES_FILE)) await fs.writeFile(BATCHES_FILE, '[]');
  if (!fsSync.existsSync(ALERTS_FILE)) await fs.writeFile(ALERTS_FILE, '[]');
  if (!fsSync.existsSync(ALERT_HISTORY_FILE)) await fs.writeFile(ALERT_HISTORY_FILE, '[]');
  if (!fsSync.existsSync(XBRL_CACHE_FILE)) await fs.writeFile(XBRL_CACHE_FILE, '{}');
  if (!fsSync.existsSync(FINANCIAL_METRICS_FILE)) await fs.writeFile(FINANCIAL_METRICS_FILE, '{}');
  if (!fsSync.existsSync(TRENDS_JOBS_FILE)) await fs.writeFile(TRENDS_JOBS_FILE, '{}');
}

async function readJSON(file) {
  return JSON.parse(await fs.readFile(file, 'utf-8'));
}

async function writeJSON(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// Backfills tier/usage fields on user records so older or hand-edited rows
// (and any record predating this field) behave like a fresh free-tier signup.
function normalizeUser(user) {
  return {
    tier: 'free',
    stripeCustomerId: null,
    stripeSubscriptionId: null,
    analysesThisMonth: 0,
    usageResetAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    // Default to an already-expired trial — this is just a safety-net default for
    // old/malformed records. Real trials are only granted explicitly at registration.
    trialEndsAt: new Date(0).toISOString(),
    ...user,
  };
}

// ── XBRL CACHE ─────────────────────────────────────────────────────────────────
// Cache extracted XBRL financial data to avoid re-fetching and parsing on every Q&A query

async function getXBRLCache() {
  try {
    return await readJSON(XBRL_CACHE_FILE);
  } catch {
    return {};
  }
}

async function setXBRLCache(data) {
  await writeJSON(XBRL_CACHE_FILE, data);
}

function getCacheKey(ticker, accessionNumber) {
  return `${ticker}:${accessionNumber}`;
}

async function getCachedXBRLData(ticker, accessionNumber) {
  const cache = await getXBRLCache();
  const key = getCacheKey(ticker, accessionNumber);
  return cache[key] || null;
}

async function setCachedXBRLData(ticker, accessionNumber, xbrlData) {
  const cache = await getXBRLCache();
  const key = getCacheKey(ticker, accessionNumber);
  cache[key] = { ...xbrlData, cachedAt: new Date().toISOString() };
  await setXBRLCache(cache);
  console.log(`[XBRL Cache] Cached data for ${key}`);
}

// ── AUTH ──────────────────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  console.log(`[AUTH] ${req.method} ${req.path} - Token: ${token ? 'present' : 'missing'}`);
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    console.log(`[AUTH] Token verified for user: ${req.user.id}`);
    next();
  } catch (err) {
    console.log(`[AUTH] Token verification failed: ${err.message}`);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── SUBSCRIPTION TIERS ──────────────────────────────────────────────────────

const FREE_ALLOWED_FORMS = ['10-K'];
const FREE_MONTHLY_LIMIT = 5;

// Resets a user's monthly usage counter in place if the reset date has passed.
// Returns true if a reset happened (caller knows it needs to persist the change).
function resetUsageIfDue(user) {
  if (new Date(user.usageResetAt) > new Date()) return false;
  user.analysesThisMonth = 0;
  user.usageResetAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  return true;
}

// A user has full Pro access if they're a paying subscriber OR still within
// their free trial window — both checked fresh against the DB, never the JWT.
function isEffectivelyPro(user) {
  return user.tier === 'pro' || new Date(user.trialEndsAt) > new Date();
}

// Checks whether a user is allowed to run an analysis for the given filing type.
// Reads tier fresh from disk on every call (not from the JWT) so upgrades/downgrades
// from Stripe webhooks take effect immediately, without waiting for token refresh.
async function checkTierAccess(userId, formType) {
  try {
    const user = await db.getUserById(userId);
    if (!user) {
      // User not found in database, but allow with free tier
      return { allowed: true, user: { id: userId, tier: 'free', analysesThisMonth: 0 }, preview: !FREE_ALLOWED_FORMS.includes(formType) };
    }

    const subscription = await db.getSubscriptionByUserId(userId);

    // Check if user is in free trial (5 days from subscription creation)
    const isInTrial = subscription &&
      subscription.created_at &&
      new Date(subscription.created_at) > new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);

    const trialEndsAt = subscription?.created_at ?
      new Date(new Date(subscription.created_at).getTime() + 5 * 24 * 60 * 60 * 1000).toISOString() :
      new Date(0).toISOString();

    const isPro = subscription?.plan_type === 'pro' || isInTrial;
    const tier = subscription?.plan_type || 'free';

    // Monthly cap is a hard block regardless of preview mode
    if (!isPro && user.analysesThisMonth >= FREE_MONTHLY_LIMIT) {
      return { allowed: false, error: { code: 'USAGE_CAP_REACHED', limit: FREE_MONTHLY_LIMIT, used: user.analysesThisMonth } };
    }

    // Locked form types get a one-section preview for free users
    if (!isPro && !FREE_ALLOWED_FORMS.includes(formType)) {
      return { allowed: true, user: { ...user, tier, trialEndsAt }, preview: true };
    }

    return { allowed: true, user: { ...user, tier, trialEndsAt } };
  } catch (err) {
    console.error('[checkTierAccess] Error:', err);
    // Allow access on error (fallback)
    return { allowed: true, user: { id: userId, tier: 'free', analysesThisMonth: 0 } };
  }
}

// Increments usage after a successful, billable analysis. Re-reads the user
// record (rather than trusting the one from checkTierAccess) since some time
// has passed running the analysis itself.
async function incrementUsage(userId) {
  const users = await readJSON(USERS_FILE);
  const idx = users.findIndex(u => u.id === userId);
  if (idx === -1) return;
  const user = normalizeUser(users[idx]);
  resetUsageIfDue(user);
  user.analysesThisMonth += 1;
  users[idx] = user;
  await writeJSON(USERS_FILE, users);
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.createUser(
      email.toLowerCase(),
      passwordHash,
      name?.trim() || email.split('@')[0]
    );

    // Create subscription record (free tier with 5-day trial)
    await db.createSubscription(user.id, null, 'free');

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    await db.createVerificationToken(user.id, verificationToken);

    // Send verification email
    const verificationLink = `https://finread.io/verify-email?token=${verificationToken}`;
    try {
      await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: email.toLowerCase(),
        subject: 'Verify your FinRead email',
        html: `
          <h2>Welcome to FinRead!</h2>
          <p>Hi ${name || 'there'},</p>
          <p>Click the link below to verify your email and start analyzing financial reports:</p>
          <a href="${verificationLink}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Verify Email</a>
          <p>Or copy this link: ${verificationLink}</p>
          <p>This link expires in 24 hours.</p>
          <p>Best,<br>The FinRead Team</p>
        `
      });
    } catch (emailErr) {
      console.error('Error sending verification email:', emailErr);
      // Don't fail registration if email fails
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, tier: 'free' },
      message: 'Account created! Check your email to verify your address.'
    });
  } catch (err) {
    if (err.message.includes('already exists')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await db.getUserByEmail(email.toLowerCase());
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Email verification endpoint
app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Verification token required' });

    const verifiedUser = await db.verifyEmail(token);
    if (!verifiedUser) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    res.json({ success: true, message: 'Email verified successfully!', user: verifiedUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const user = await db.getUserByEmailForReset(email.toLowerCase());
    if (!user) {
      return res.status(400).json({ error: 'Email not found' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    await db.createPasswordResetToken(user.id, resetToken);

    // Send reset email
    const resetLink = `https://finread.io/reset-password?token=${resetToken}`;
    try {
      await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: email.toLowerCase(),
        subject: 'Reset your FinRead password',
        html: `
          <h2>Password Reset Request</h2>
          <p>Hi ${user.email},</p>
          <p>Click the link below to reset your password:</p>
          <a href="${resetLink}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
          <p>Or copy this link: ${resetLink}</p>
          <p>This link expires in 1 hour.</p>
          <p>If you didn't request this, you can ignore this email.</p>
          <p>Best,<br>The FinRead Team</p>
        `
      });
    } catch (emailErr) {
      console.error('Error sending reset email:', emailErr);
    }

    res.json({ success: true, message: 'Password reset email sent! Check your inbox.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.resetPassword(token, passwordHash);

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    res.json({ success: true, message: 'Password reset successfully!', email: user.email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'All fields required' });
    }

    // Send email to admin
    try {
      await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: 'joeq415@gmail.com',
        subject: `FinRead Contact: ${subject}`,
        html: `
          <h2>New Contact Form Submission</h2>
          <p><strong>From:</strong> ${name} (${email})</p>
          <p><strong>Subject:</strong> ${subject}</p>
          <hr>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, '<br>')}</p>
          <hr>
          <p style="font-size:0.9rem; color:#666;">
            Reply to: ${email}
          </p>
        `
      });
    } catch (emailErr) {
      console.error('Error sending contact email:', emailErr);
    }

    res.json({ success: true, message: 'Thank you for contacting us! We\'ll get back to you soon.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── EDGAR ─────────────────────────────────────────────────────────────────────

const EDGAR_UA = { 'User-Agent': 'FinRead educational-app contact@finread.example.com' };

async function getCompanyCIK(ticker) {
  const res = await fetch('https://www.sec.gov/files/company_tickers.json', { headers: EDGAR_UA });
  if (!res.ok) throw new Error('Could not reach SEC EDGAR. Please try again.');
  const data = await res.json();
  const entry = Object.values(data).find(c => c.ticker === ticker.toUpperCase());
  if (!entry) throw new Error(`Ticker "${ticker.toUpperCase()}" not found in SEC database.`);
  return { cik: String(entry.cik_str).padStart(10, '0'), name: entry.title };
}

async function getRecentFilings(cik, formType) {
  const res = await fetch(`https://data.sec.gov/submissions/CIK${cik}.json`, { headers: EDGAR_UA });
  if (!res.ok) throw new Error('Failed to fetch filing history from SEC.');
  const data = await res.json();

  const recent = data.filings.recent;
  const results = [];
  for (let i = 0; i < recent.form.length && results.length < 5; i++) {
    const form = recent.form[i];
    const match =
      form === formType ||
      (formType === '10-K' && (form === '10-K' || form === '10-K/A')) ||
      (formType === '10-Q' && form === '10-Q') ||
      (formType === '8-K' && form === '8-K') ||
      (formType === 'DEF 14A' && form === 'DEF 14A') ||
      (formType === '20-F' && form === '20-F') ||
      (formType === '13-F' && (form === '13F-HR' || form === '13F-HR/A'));
    if (match) {
      results.push({
        accessionNumber: recent.accessionNumber[i],
        filingDate: recent.filingDate[i],
        form: recent.form[i],
        primaryDocument: recent.primaryDocument[i],
      });
    }
  }
  return { companyName: data.name, cik, filings: results };
}

function stripHtml(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ')
    .replace(/&#160;/g, ' ').replace(/&#8217;/g, "'").replace(/&#8220;/g, '"').replace(/&#8221;/g, '"')
    .replace(/&#8212;/g, '—').replace(/&#\d+;/g, ' ').replace(/&[a-z]+;/g, ' ')
    .replace(/\s{3,}/g, '\n\n')
    .trim();
}

async function fetchFilingIndex(cik, accessionNumber) {
  const numericCik = cik.replace(/^0+/, '');
  const cleanAcc = accessionNumber.replace(/-/g, '');
  const idxUrl = `https://www.sec.gov/Archives/edgar/data/${numericCik}/${cleanAcc}/${accessionNumber}-index.htm`;
  const res = await fetch(idxUrl, { headers: EDGAR_UA });
  return res.ok ? res.text() : '';
}

// Extract Table of Contents from HTML and map financial statement sections to page numbers
// Returns: { balanceSheetPage, incomeStatementPage, cashFlowPage }
function extractTableOfContents(html) {
  // Remove script and style tags
  let cleanHtml = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                       .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '');

  // Look for TOC section — typically marked with "contents", "table of contents", or "index"
  const tocMatch = cleanHtml.match(/<(?:div|section)[^>]*>[\s\S]{0,10000}?(?:contents|table of contents|index)[\s\S]{0,15000}?<\/(?:div|section)>/i);
  const tocSection = tocMatch ? tocMatch[0] : cleanHtml.substring(0, 30000); // Fallback: first 30k chars

  const toc = {};

  // Search for financial statement entries in TOC with page numbers
  // Patterns: "Consolidated Balance Sheets ... 45" or "Item 8. Financial Statements ... 50"
  const patterns = [
    { key: 'balance', regex: /consolidated\s+balance\s+sheets?[^\d]*?(\d+)/i },
    { key: 'income', regex: /consolidated\s+statements?\s+of\s+(?:earnings|income)[^\d]*?(\d+)/i },
    { key: 'cashflow', regex: /consolidated\s+statements?\s+of\s+cash\s+flows?[^\d]*?(\d+)/i },
  ];

  for (const { key, regex } of patterns) {
    const match = tocSection.match(regex);
    if (match && match[1]) {
      const pageNum = parseInt(match[1], 10);
      toc[key] = pageNum;
      console.log(`[extractTOC] Found "${key}" at page ${pageNum}`);
    }
  }

  return toc;
}

// Estimate character position in text based on page number
// Rough heuristic: average ~2700 chars per page in SEC filings
function estimateCharPositionFromPage(pageNum) {
  return Math.max(0, (pageNum - 1) * 2700);
}

// Fetch and parse XBRL instance document to extract balance sheet metrics
// Returns: { totalAssets, currentAssets, currentLiabilities, totalLiabilities, equity }
async function fetchBalanceSheetFromXBRL(cik, accessionNumber) {
  try {
    const numericCik = cik.replace(/^0+/, '');
    const cleanAcc = accessionNumber.replace(/-/g, '');
    const baseUrl = `https://www.sec.gov/Archives/edgar/data/${numericCik}/${cleanAcc}`;

    // Fetch the filing index to find the XBRL instance document
    const indexUrl = `${baseUrl}/${accessionNumber}-index.htm`;
    const indexRes = await fetch(indexUrl, { headers: EDGAR_UA });
    const indexHtml = await indexRes.text();

    // Find the XBRL instance document - flexible matching for different SEC formats
    // Try specific patterns first (XBRL instance docs), then fall back to any .xml
    let xmlMatch = indexHtml.match(/href="([^"]*-xbrl\.xml|[^"]*_inst\.xml)"/i);
    if (!xmlMatch) {
      // Fallback: find the first .xml file (usually the instance doc)
      xmlMatch = indexHtml.match(/href="([^"]+\.xml)"/i);
    }
    if (!xmlMatch) {
      console.warn('[fetchBalanceSheetFromXBRL] Could not find XBRL instance document');
      return null;
    }

    let xbrlFile = xmlMatch[1];
    // If xbrlFile is a full path, extract just the filename; otherwise use as-is
    if (xbrlFile.includes('/')) {
      xbrlFile = xbrlFile.split('/').pop();
    }
    const xbrlUrl = `${baseUrl}/${xbrlFile}`;

    console.log(`[fetchBalanceSheetFromXBRL] Fetching XBRL: ${xbrlUrl}`);
    const xbrlRes = await fetch(xbrlUrl, { headers: EDGAR_UA });
    const xbrlXml = await xbrlRes.text();

    // Extract balance sheet metrics using regex patterns for XBRL tags
    // XBRL format: <us-gaap:Assets contextRef="..." unitRef="USD">8390000000</us-gaap:Assets>
    const metrics = extractXBRLMetrics(xbrlXml);

    return metrics;
  } catch (err) {
    console.error('[fetchBalanceSheetFromXBRL] Error:', err.message);
    return null;
  }
}

// Wrapper for parallel XBRL fetching during analysis
async function fetchXBRLMetricsAsync(cik, accessionNumber, formType) {
  try {
    const metrics = await fetchAllXBRLMetrics(cik, accessionNumber);
    if (metrics) {
      console.log(`[fetchXBRLMetricsAsync] Successfully fetched XBRL metrics for ${formType}`);
    }
    return metrics;
  } catch (err) {
    console.error(`[fetchXBRLMetricsAsync] XBRL fetch failed for ${formType}:`, err.message);
    return null;
  }
}

// Fetch all XBRL metrics (profitability, efficiency, balance sheet) from SEC EDGAR
async function fetchAllXBRLMetrics(cik, accessionNumber) {
  try {
    const numericCik = cik.replace(/^0+/, '');
    const cleanAcc = accessionNumber.replace(/-/g, '');
    const baseUrl = `https://www.sec.gov/Archives/edgar/data/${numericCik}/${cleanAcc}`;

    // Fetch the filing index to find the XBRL instance document
    const indexUrl = `${baseUrl}/${accessionNumber}-index.htm`;
    console.log(`[fetchAllXBRLMetrics] Fetching index: ${indexUrl}`);
    const indexRes = await fetch(indexUrl, { headers: EDGAR_UA });
    if (!indexRes.ok) {
      console.warn('[fetchAllXBRLMetrics] Index file not found, XBRL extraction not available');
      return null;
    }
    const indexHtml = await indexRes.text();

    // Find the XBRL instance document - flexible matching for different SEC formats
    // Try specific patterns first (XBRL instance docs), then fall back to any .xml
    let xmlMatch = indexHtml.match(/href="([^"]*(?:-xbrl|_inst)\.xml)"/i);
    if (!xmlMatch) {
      // Fallback: find .xml files that look like instance documents
      xmlMatch = indexHtml.match(/href="([^"]+?(?:xbrl|inst)[^"]*\.xml)"/i);
    }
    if (!xmlMatch) {
      // Last resort: find any .xml file
      xmlMatch = indexHtml.match(/href="([^"]+\.xml)"/i);
    }
    if (!xmlMatch) {
      console.log('[fetchAllXBRLMetrics] No XBRL instance document found in index. XBRL extraction unavailable for this filing.');
      return null;
    }

    let xbrlFile = xmlMatch[1];
    // If xbrlFile is a full path, extract just the filename; otherwise use as-is
    if (xbrlFile.includes('/')) {
      xbrlFile = xbrlFile.split('/').pop();
    }
    const xbrlUrl = `${baseUrl}/${xbrlFile}`;

    console.log(`[fetchAllXBRLMetrics] Attempting XBRL extraction from: ${xbrlUrl}`);
    const xbrlRes = await fetch(xbrlUrl, { headers: EDGAR_UA, timeout: 10000 });
    if (!xbrlRes.ok) {
      console.log('[fetchAllXBRLMetrics] Could not fetch XBRL file, falling back to HTML extraction');
      return null;
    }
    const xbrlXml = await xbrlRes.text();

    // Extract all metrics (profitability, efficiency, balance sheet) using flexible regex patterns
    const metrics = extractAllXBRLMetrics(xbrlXml);

    if (!metrics || Object.values(metrics).every(v => v === null)) {
      console.log('[fetchAllXBRLMetrics] XBRL file found but no metrics extracted. Will use HTML extraction instead.');
      return null;
    }

    console.log('[fetchAllXBRLMetrics] Successfully extracted metrics from XBRL');
    return metrics;
  } catch (err) {
    console.log(`[fetchAllXBRLMetrics] Extraction failed (${err.message}), falling back to HTML extraction`);
    return null;
  }
}

// Parse XBRL XML and extract balance sheet metrics
function extractXBRLMetrics(xbrlXml) {
  const metrics = {};

  // Helper to extract metric value from XBRL (flexible to handle different formats)
  const extractMetric = (tagName, contexts) => {
    // Try with specific contexts and flexible unitRef
    for (const context of contexts) {
      const pattern = new RegExp(`<us-gaap:${tagName}[^>]*context="${context}"[^>]*unitRef="[^"]*"[^>]*>([\\d-]+)<`, 'i');
      const match = xbrlXml.match(pattern);
      if (match) {
        const value = parseInt(match[1], 10);
        return value / 1000000000;
      }
    }

    // Fallback: find any context (more flexible)
    const flexiblePattern = new RegExp(`<us-gaap:${tagName}[^>]*>([\\d-]+)<`, 'i');
    const match = flexiblePattern.exec(xbrlXml);
    if (match) {
      const value = parseInt(match[1], 10);
      return value / 1000000000;
    }

    return null;
  };

  // Try to find the current period context (usually something like "CurrentYearDuration" or "FY2024")
  // XBRL uses contextRef attributes like "Current_FiscalYearDuration" or similar
  const contextMatch = xbrlXml.match(/context="([^"]*(?:Current|FY|2024|Duration)[^"]*)"/i);
  const currentContext = contextMatch ? contextMatch[1] : 'Current_FiscalYearDuration';

  // Extract key balance sheet metrics
  metrics.totalAssets = extractMetric('Assets', [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration']);
  metrics.currentAssets = extractMetric('AssetsCurrent', [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration']);
  metrics.totalLiabilities = extractMetric('Liabilities', [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration']);
  metrics.currentLiabilities = extractMetric('LiabilitiesCurrent', [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration']);
  metrics.equity = extractMetric('StockholdersEquity', [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration']);

  console.log('[extractXBRLMetrics] Extracted:', {
    totalAssets: metrics.totalAssets,
    currentAssets: metrics.currentAssets,
    totalLiabilities: metrics.totalLiabilities,
    currentLiabilities: metrics.currentLiabilities,
    equity: metrics.equity
  });

  return metrics;
}

// Update sections' key_figures with accurate XBRL data while preserving Claude's analysis
function updateSectionsWithXBRLData(sections, xbrlMetrics) {
  // Map section keys to XBRL metrics
  const metricMap = {
    revenue: { figures: [{ label: 'Total Revenue', value: xbrlMetrics.revenue }] },
    income: { figures: [
      { label: 'Net Income', value: xbrlMetrics.netIncome },
      { label: 'Operating Income', value: xbrlMetrics.operatingIncome },
      { label: 'Gross Profit', value: xbrlMetrics.grossProfit }
    ] },
    cashflow: { figures: [
      { label: 'Operating Cash Flow', value: xbrlMetrics.operatingCashFlow },
      { label: 'Capital Expenditures', value: xbrlMetrics.capex },
      { label: 'Free Cash Flow', value: xbrlMetrics.freeCashFlow }
    ] },
    balance: { figures: [
      { label: 'Total Assets', value: xbrlMetrics.totalAssets },
      { label: 'Current Assets', value: xbrlMetrics.currentAssets },
      { label: 'Total Liabilities', value: xbrlMetrics.totalLiabilities },
      { label: 'Shareholders Equity', value: xbrlMetrics.equity }
    ] }
  };

  // Update each section with XBRL data
  for (const [sectionKey, mapping] of Object.entries(metricMap)) {
    if (sections[sectionKey] && mapping.figures && sections[sectionKey].key_figures) {
      // Preserve Claude's original key_figures and only update the monetary values with XBRL data
      // This keeps the change/YoY context from Claude's analysis instead of replacing with misleading "+0%"
      sections[sectionKey].key_figures = sections[sectionKey].key_figures.map(claudeFig => {
        const xbrlMatch = mapping.figures.find(xbrlFig =>
          xbrlFig.label.toLowerCase().includes(claudeFig.label.toLowerCase().split(/\s+/)[0])
        );
        if (xbrlMatch && xbrlMatch.value !== null && xbrlMatch.value !== undefined) {
          return {
            ...claudeFig,
            value: `$${Math.abs(xbrlMatch.value).toFixed(2)}B`,
            tooltip: claudeFig.tooltip ? `${claudeFig.tooltip} (updated with SEC XBRL data)` : `Updated with SEC XBRL data`
          };
        }
        return claudeFig;
      });
      console.log(`[updateSectionsWithXBRLData] Updated ${sectionKey} key_figures values with XBRL data`);
    }
  }
}

// Extract all key financial metrics from XBRL for use in Key Figures
function extractAllXBRLMetrics(xbrlXml) {
  const metrics = {};

  const extractMetric = (tagNames, contexts) => {
    // Handle both single tag name (string) and multiple alternatives (array)
    const tags = Array.isArray(tagNames) ? tagNames : [tagNames];

    for (const tagName of tags) {
      // Try to find the tag with various context and unitRef patterns
      // First, try with specific contexts and USD unit
      for (const context of contexts) {
        const pattern = new RegExp(`<us-gaap:${tagName}[^>]*context="${context}"[^>]*unitRef="[^"]*"[^>]*>([-\\d.]+)<`, 'i');
        const match = xbrlXml.match(pattern);
        if (match && match[1]) {
          const value = parseFloat(match[1].replace(/,/g, ''));
          return !isNaN(value) ? value / 1000000000 : null;
        }
      }

      // Try with context but any unitRef
      for (const context of contexts) {
        const pattern = new RegExp(`<us-gaap:${tagName}[^>]*context="${context}"[^>]*>([-\\d.]+)<`, 'i');
        const match = xbrlXml.match(pattern);
        if (match && match[1]) {
          const value = parseFloat(match[1].replace(/,/g, ''));
          return !isNaN(value) ? value / 1000000000 : null;
        }
      }

      // Fallback: find any instance of the tag (most flexible)
      const flexiblePattern = new RegExp(`<us-gaap:${tagName}[^>]*>([-\\d.]+)<`, 'i');
      const match = flexiblePattern.exec(xbrlXml);
      if (match && match[1]) {
        const value = parseFloat(match[1].replace(/,/g, ''));
        return !isNaN(value) ? value / 1000000000 : null;
      }
    }

    return null;
  };

  const contextMatch = xbrlXml.match(/context="([^"]*(?:Current|FY|2024|Duration)[^"]*)"/i);
  const currentContext = contextMatch ? contextMatch[1] : 'Current_FiscalYearDuration';
  const contexts = [currentContext, 'Current_FiscalYearDuration', 'FY2024', 'Duration'];

  // Income statement metrics
  metrics.revenue = extractMetric(['Revenues', 'RevenuefromContractwithCustomers', 'Revenues_Parent'], contexts);
  metrics.netIncome = extractMetric(['NetIncomeLoss', 'ProfitLoss', 'NetIncome', 'NetIncomeAttributableToParent'], contexts);
  metrics.operatingIncome = extractMetric(['OperatingIncomeLoss', 'OperatingIncome', 'OperatingIncomeFromSpecialReports'], contexts);
  metrics.grossProfit = extractMetric(['GrossProfit', 'GrossProfitLoss'], contexts);

  // Cash flow metrics with multiple alternative tag names for robustness
  metrics.operatingCashFlow = extractMetric([
    'NetCashProvidedByUsedInOperatingActivities',
    'CashFlowsFromOperatingActivities',
    'NetCashFromOperatingActivities',
    'CashProvidedByOperatingActivities',
    'NetCashFromOperations',
    'OperatingCashFlow',
    'NetCashFromOperatingActivities_Parent',
    'CashProvidedByUsedInOperatingActivitiesAbstract'
  ], contexts);

  metrics.capex = extractMetric([
    'PaymentsToAcquirePropertyPlantAndEquipment',
    'CapitalExpenditures',
    'PaymentsForCapitalExpenditures',
    'PaymentsToAcquirePPE',
    'PaymentsToAcquirePropertyAndEquipment',
    'CashOutflowsFromCapitalExpenditures',
    'PurchasesOfPropertyAndEquipment',
    'PaymentForCapitalExpenditures'
  ], contexts);

  metrics.freeCashFlow = metrics.operatingCashFlow && metrics.capex ?
    metrics.operatingCashFlow - (metrics.capex > 0 ? metrics.capex : Math.abs(metrics.capex)) : null;

  // Balance sheet metrics
  metrics.totalAssets = extractMetric(['Assets', 'AssetsAbstract', 'Assets_Parent'], contexts);
  metrics.currentAssets = extractMetric(['AssetsCurrent', 'CurrentAssets', 'CurrentAssets_Parent'], contexts);
  metrics.totalLiabilities = extractMetric(['Liabilities', 'LiabilitiesAbstract', 'Liabilities_Parent', 'LiabilitiesCurrent_Parent'], contexts);
  metrics.currentLiabilities = extractMetric(['LiabilitiesCurrent', 'CurrentLiabilities', 'CurrentLiabilities_Parent'], contexts);
  metrics.equity = extractMetric(['StockholdersEquity', 'Equity', 'StockholdersEquity_Parent', 'Equity_Parent'], contexts);

  // Debug logging for cash flow
  if (metrics.operatingCashFlow === 0 || metrics.capex === 0) {
    console.log('[extractAllXBRLMetrics] ⚠️ Cash Flow Extraction Debug:', {
      operatingCashFlow: metrics.operatingCashFlow,
      capex: metrics.capex,
      contextsCount: contexts.length,
      firstFewContexts: contexts.slice(0, 3).map(c => c.label)
    });
  }

  console.log('[extractAllXBRLMetrics] Revenue:', metrics.revenue, 'NetIncome:', metrics.netIncome, 'OperatingCF:', metrics.operatingCashFlow, 'CapEx:', metrics.capex);

  return metrics;
}

// Format extracted XBRL metrics into readable text for Q&A
function formatXBRLForQA(metrics, ticker, formType) {
  const format = (value) => {
    if (!value) return 'N/A';
    if (value > 1000) return `$${(value / 1000).toFixed(1)}T`;
    if (value > 1) return `$${value.toFixed(1)}B`;
    return `$${(value * 1000).toFixed(1)}M`;
  };

  let text = `=== ${ticker} Financial Data from ${formType} ===\n\n`;

  text += `BALANCE SHEET:\n`;
  text += `- Total Assets: ${format(metrics.totalAssets)}\n`;
  text += `- Current Assets: ${format(metrics.currentAssets)}\n`;
  text += `- Total Liabilities: ${format(metrics.totalLiabilities)}\n`;
  text += `- Current Liabilities: ${format(metrics.currentLiabilities)}\n`;
  text += `- Stockholders' Equity: ${format(metrics.equity)}\n\n`;

  text += `INCOME STATEMENT:\n`;
  text += `- Revenue: ${format(metrics.revenue)}\n`;
  text += `- Gross Profit: ${format(metrics.grossProfit)}\n`;
  text += `- Operating Income: ${format(metrics.operatingIncome)}\n`;
  text += `- Net Income: ${format(metrics.netIncome)}\n\n`;

  text += `CASH FLOW:\n`;
  text += `- Operating Cash Flow: ${format(metrics.operatingCashFlow)}\n`;
  text += `- Capital Expenditures: ${format(metrics.capex)}\n`;
  text += `- Free Cash Flow: ${format(metrics.freeCashFlow)}\n\n`;

  return text;
}

// Pre-extract and cache all XBRL financial data for a filing
async function preExtractXBRLData(cik, accessionNumber, ticker, formType) {
  try {
    console.log(`[preExtractXBRL] Starting extraction for ${ticker} ${formType}`);

    // Check if already cached
    const cached = await getCachedXBRLData(ticker, accessionNumber);
    if (cached) {
      console.log(`[preExtractXBRL] Found existing cache for ${ticker}:${accessionNumber}`);
      return cached;
    }

    // Fetch and extract XBRL metrics
    const metrics = await fetchAllXBRLMetrics(cik, accessionNumber);

    if (!metrics || Object.values(metrics).every(v => v === null)) {
      console.warn(`[preExtractXBRL] No metrics extracted for ${ticker}`);
      return null;
    }

    // Format for Q&A
    const qaText = formatXBRLForQA(metrics, ticker, formType);

    // Cache the result
    const xbrlData = { metrics, qaText, formType, ticker };
    await setCachedXBRLData(ticker, accessionNumber, xbrlData);

    console.log(`[preExtractXBRL] Successfully extracted and cached data for ${ticker}`);
    return xbrlData;
  } catch (err) {
    console.error(`[preExtractXBRL] Error for ${ticker}:`, err.message);
    return null;
  }
}

// Returns { text, sourceUrl } — sourceUrl points readers to the most useful
// human-readable page for this filing type, used for the "View Original
// Filing" link. Not a per-paragraph anchor (SEC HTML docs don't reliably
// support those) — just the best single page to verify the analysis against.
async function fetchFilingText(cik, accessionNumber, primaryDocument, formType) {
  const numericCik = cik.replace(/^0+/, '');
  const cleanAcc = accessionNumber.replace(/-/g, '');
  const base = `https://www.sec.gov/Archives/edgar/data/${numericCik}/${cleanAcc}`;
  const indexUrl = `${base}/${accessionNumber}-index.htm`;

  // ── 13-F: real holdings are in a separate XML infotable, not the cover page ──
  if (formType === '13-F' || formType === '13F-HR') {
    const currentRows = await fetch13FRows(cik, accessionNumber);
    if (currentRows.length) {
      const holdingsText = rows13FToText(currentRows);
      let changesText = 'No prior-quarter 13-F filing available for comparison.';
      try {
        const prior = await getPrior13FFiling(cik, accessionNumber);
        if (prior) {
          const priorRows = await fetch13FRows(cik, prior.accessionNumber);
          if (priorRows.length) {
            changesText = diff13FToText(diff13F(currentRows, priorRows));
          }
        }
      } catch (err) {
        console.error('13F prior-quarter diff failed:', err.message);
      }
      // Holdings come from XML, not human-readable — link to the filing index instead.
      return { text: `${holdingsText}\n\n===CHANGES===\n${changesText}`, sourceUrl: indexUrl };
    }
  }

  // ── 8-K: main doc is a cover page; real content is in EX-99.1 exhibit ──
  if (formType === '8-K') {
    const idxHtml = await fetchFilingIndex(cik, accessionNumber);
    // Find exhibit htm files in the filing (not the primary doc, not ix? viewer links)
    const exFiles = [...idxHtml.matchAll(/href="(\/Archives\/edgar\/data\/[^"]+\.htm[l]?)"/gi)]
      .map(m => m[1])
      .filter(p => !p.includes('/ix?'));
    // Prefer explicit exhibit99 / ex99 file, otherwise take first non-primary htm
    const primary = primaryDocument.toLowerCase();
    const exFile = exFiles.find(p => /ex-?99|exhibit99/i.test(p))
                || exFiles.find(p => !p.toLowerCase().endsWith(primary));
    if (exFile) {
      const exRes = await fetch(`https://www.sec.gov${exFile}`, { headers: EDGAR_UA });
      if (exRes.ok) {
        const exHtml = await exRes.text();
        // Link directly to the exhibit the analysis was actually drawn from.
        return { text: stripHtml(exHtml).substring(0, 120000), sourceUrl: `https://www.sec.gov${exFile}` };
      }
    }
    // No exhibit found/fetched — fall through to the default primary-document fetch below.
  }

  // ── Default: fetch primary document ──
  const docUrl = `${base}/${primaryDocument}`;
  const res = await fetch(docUrl, { headers: EDGAR_UA });
  if (!res.ok) throw new Error(`Failed to fetch filing document (HTTP ${res.status}).`);
  const html = await res.text();

  // Extract Table of Contents to locate financial statement sections
  const toc = extractTableOfContents(html);

  // CRITICAL: For 10-K/20-F, we need to extract actual financial statement DATA
  // The issue is that financial statements might be in tables, formatted text, or other structures
  // So we'll extract multiple strategies to ensure we get the real numbers
  let enrichedText = '';

  if (formType === '10-K' || formType === '20-F') {
    console.log(`[fetchFilingText] Starting financial data extraction for ${formType}. HTML size: ${html.length}`);

    // Strategy 1: Extract all tables (they often contain financial data)
    const tableRegex = /<table[^>]*>([\s\S]{0,60000}?)<\/table>/gi;
    let tableMatch;
    const tables = [];
    let tableSearchCount = 0;

    while ((tableMatch = tableRegex.exec(html)) !== null) {
      tableSearchCount++;
      const tableHtml = tableMatch[0];
      // Check if this looks like a financial statement
      if (/(?:Assets|Liabilities|Equity|Revenue|Income|Cash|Operating|Investing|Financing|Total)/i.test(tableHtml)) {
        tables.push(stripHtml(tableHtml));
      }
    }

    console.log(`[fetchFilingText] Table search: found ${tableSearchCount} tables total, ${tables.length} matched financial keywords`);

    if (tables.length > 0) {
      enrichedText += '\n=== FINANCIAL STATEMENT TABLES ===\n' + tables.join('\n\n');
    }

    // Strategy 2: Search for and extract sections with specific headers
    const sectionPatterns = [
      { name: 'BALANCE SHEET', pattern: /(?:CONSOLIDATED BALANCE SHEETS?|BALANCE SHEETS?|Assets[\s\S]{0,500}Liabilities)[\s\S]{0,50000}?(?=\n\n[A-Z][A-Z\s]*\n|Item|CONSOLIDATED|$)/i },
      { name: 'INCOME STATEMENT', pattern: /(?:CONSOLIDATED STATEMENTS? OF (?:OPERATIONS|EARNINGS|INCOME)|INCOME STATEMENTS?|Revenues?[\s\S]{0,500}Net Income)[\s\S]{0,50000}?(?=\n\n[A-Z][A-Z\s]*\n|Item|CONSOLIDATED|$)/i },
      { name: 'CASH FLOW', pattern: /(?:CONSOLIDATED STATEMENTS? OF CASH FLOWS?|CASH FLOW STATEMENTS?|Operating Activities[\s\S]{0,500}Investing)[\s\S]{0,50000}?(?=\n\n[A-Z][A-Z\s]*\n|Item|CONSOLIDATED|$)/i }
    ];

    let sectionsFound = 0;
    for (const section of sectionPatterns) {
      const match = html.match(section.pattern);
      if (match && match[0].length > 200) {
        const extracted = stripHtml(match[0]);
        enrichedText += `\n=== ${section.name} ===\n${extracted}\n`;
        sectionsFound++;
        console.log(`[fetchFilingText] Found ${section.name} section (${match[0].length} chars)`);
      }
    }

    console.log(`[fetchFilingText] Section search: found ${sectionsFound}/3 financial statement sections`);
  }

  // Strip main HTML to text
  const text = stripHtml(html);

  // Combine: main text first, then enriched financial data at the end
  // This ensures Claude sees everything without overwhelming context
  let finalText = text;
  if (enrichedText.length > 0) {
    finalText = text + '\n\n' + enrichedText;
  }

  // For 10-K/20-F, use full document (they contain all the data we need)
  // For other types, use reasonable limits
  let cap = finalText.length;
  if (formType === '10-K' || formType === '20-F') {
    // Use the full document - we need everything for proper financial analysis
    cap = finalText.length;
  } else {
    cap = Math.min(finalText.length, 500000);
  }

  console.log(`[fetchFilingText] ${formType} final: text=${text.length}, enriched=${enrichedText.length}, cap=${cap}, total=${finalText.length}`);

  return { text: finalText.substring(0, cap), sourceUrl: docUrl, toc };
}

// Parse 13-F XML holdings into structured rows: [{ name, valueM, shares }]
// SEC reports <value> in raw USD as of the 2023 schema update (was thousands before).
function parse13FRows(xml) {
  const rows = [];
  const re = /<infoTable>([\s\S]*?)<\/infoTable>/gi;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const get = (tag) => { const t = new RegExp(`<${tag}>([^<]+)</${tag}>`,'i').exec(m[1]); return t ? t[1].trim() : ''; };
    const name = get('nameOfIssuer');
    const cusip = get('cusip');
    const value = get('value');
    const shares = get('sshPrnamt');
    if (name && value) {
      const valueM = parseInt(value) / 1000000;
      // Key on CUSIP (stable security identifier) since issuer name spelling can
      // vary slightly between quarters (e.g. "L P" vs "LP") and across sub-managers.
      const key = cusip || name;
      const existing = rows.find(r => r.key === key);
      if (existing) {
        existing.valueM += valueM;
        existing.shares += parseInt(shares) || 0;
      } else {
        rows.push({ key, name, valueM, shares: parseInt(shares) || 0 });
      }
    }
  }
  rows.sort((a, b) => b.valueM - a.valueM);
  return rows;
}

// Convert structured rows into a readable text block for Claude
function rows13FToText(rows) {
  const total = rows.reduce((s, r) => s + r.valueM, 0);
  const lines = rows.slice(0, 50).map(r => `${r.name}: $${r.valueM.toFixed(1)}M (${r.shares.toLocaleString()} shares)`);
  return `13F Holdings Report\nTotal portfolio value: $${(total/1000).toFixed(1)}B\nNumber of positions: ${rows.length}\n\nTop Holdings:\n${lines.join('\n')}`;
}

function parse13F(xml) {
  return rows13FToText(parse13FRows(xml));
}

// Find the prior quarter's 13F-HR filing (skip amendments and the current one)
// so we can diff holdings quarter-over-quarter.
async function getPrior13FFiling(cik, currentAccessionNumber) {
  const res = await fetch(`https://data.sec.gov/submissions/CIK${cik}.json`, { headers: EDGAR_UA });
  if (!res.ok) return null;
  const data = await res.json();
  const recent = data.filings.recent;
  let passedCurrent = false;
  for (let i = 0; i < recent.form.length; i++) {
    if (recent.form[i] !== '13F-HR') continue;
    if (recent.accessionNumber[i] === currentAccessionNumber) { passedCurrent = true; continue; }
    if (passedCurrent) {
      return { accessionNumber: recent.accessionNumber[i], filingDate: recent.filingDate[i] };
    }
  }
  return null;
}

// Fetch and parse a 13F filing's holdings XML into structured rows.
async function fetch13FRows(cik, accessionNumber) {
  const idxHtml = await fetchFilingIndex(cik, accessionNumber);
  const xmlFiles = [...idxHtml.matchAll(/href="(\/Archives\/edgar\/data\/[^"]+\.xml)"/gi)]
    .map(m => m[1])
    .filter(p => !p.includes('xslForm') && !p.includes('primary_doc'));
  if (!xmlFiles.length) return [];
  const xmlRes = await fetch(`https://www.sec.gov${xmlFiles[0]}`, { headers: EDGAR_UA });
  if (!xmlRes.ok) return [];
  const xml = await xmlRes.text();
  return parse13FRows(xml);
}

// Diff two quarters of 13F holdings into new/exited/increased/decreased positions.
function diff13F(currentRows, priorRows) {
  const priorMap = new Map(priorRows.map(r => [r.key, r]));
  const currentMap = new Map(currentRows.map(r => [r.key, r]));

  const newPositions = currentRows.filter(r => !priorMap.has(r.key))
    .sort((a, b) => b.valueM - a.valueM).slice(0, 5);
  const exited = priorRows.filter(r => !currentMap.has(r.key))
    .sort((a, b) => b.valueM - a.valueM).slice(0, 5);

  const changed = currentRows
    .filter(r => priorMap.has(r.key))
    .map(r => ({ name: r.name, priorM: priorMap.get(r.key).valueM, currentM: r.valueM, deltaM: r.valueM - priorMap.get(r.key).valueM }));

  const increased = changed.filter(r => r.deltaM > 0).sort((a, b) => b.deltaM - a.deltaM).slice(0, 5);
  const decreased = changed.filter(r => r.deltaM < 0).sort((a, b) => a.deltaM - b.deltaM).slice(0, 5);

  return { newPositions, exited, increased, decreased };
}

function diff13FToText(diff) {
  const fmt = (v) => `$${v.toFixed(1)}M`;
  const section = (title, lines) => lines.length ? `${title}:\n${lines.join('\n')}\n\n` : `${title}: none\n\n`;
  return (
    section('NEW POSITIONS (added this quarter)', diff.newPositions.map(r => `${r.name}: ${fmt(r.valueM)} (${r.shares.toLocaleString()} shares)`)) +
    section('EXITED POSITIONS (sold off completely)', diff.exited.map(r => `${r.name}: was ${fmt(r.valueM)} (${r.shares.toLocaleString()} shares)`)) +
    section('INCREASED POSITIONS (added to existing stake)', diff.increased.map(r => `${r.name}: ${fmt(r.priorM)} → ${fmt(r.currentM)} (+${fmt(r.deltaM)})`)) +
    section('DECREASED POSITIONS (trimmed existing stake)', diff.decreased.map(r => `${r.name}: ${fmt(r.priorM)} → ${fmt(r.currentM)} (${fmt(r.deltaM)})`))
  ).trim();
}

app.get('/api/edgar/search', async (req, res) => {
  try {
    const { ticker, form = '10-K' } = req.query;
    if (!ticker) return res.status(400).json({ error: 'Ticker symbol is required' });
    const { cik, name } = await getCompanyCIK(ticker);
    const result = await getRecentFilings(cik, form);
    res.json({ ...result, name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── AI ANALYSIS ───────────────────────────────────────────────────────────────

// Section definitions per filing type — each includes a figures hint so Claude
// knows exactly what numbers to extract and avoids hallucinating irrelevant ones.
const FILING_SECTIONS = {
  '10-K': {
    revenue:   {
      label: 'Revenue',
      prompt: 'Consolidated Statements of Operations OR Consolidated Statements of Earnings (search financial statements section). For financial services companies (brokers, exchanges, fintech, payment processors): total revenue is usually at the top — may be labeled "Total net revenues", "Total revenues", "Total operating revenues", or for fintech/brokers "Total transaction revenues" or "Net revenues" (showing all revenue streams combined). Look for the top-line revenue figure before expenses.',
      figures: 'Total Net Sales or Total Revenue (dollar amount from the top of income statement), Net Income (dollar amount at bottom of statement), and Earnings Per Share diluted (dollar amount). Pull directly from the income statement table. For fintech/brokers, total revenue should aggregate all business segments/revenue streams.',
    },
    income:    {
      label: 'Operating Income',
      prompt: 'Consolidated Statements of Operations OR Consolidated Statements of Earnings (search entire filing thoroughly). NOTE: For financial services companies (brokers, exchanges, fintech), operating income structure may be different — look for: "Operating Expenses" or "Total Operating Expenses" as a line item, and then work backwards to find "Operating Income" or "Income from Operations". May also be labeled "Income Before Taxes" or "Earnings Before Taxes (EBT)" as a proxy for operating performance.',
      figures: 'CRITICAL: Return exactly 4 figures from the income statement: (1) "Gross Profit" — for product-based companies, this is revenues minus cost of goods sold. For financial services/brokers: may not have traditional gross profit line — if so, use total revenues as a proxy OR look for "Total revenue" minus "Cost of revenues" section. (2) "Operating Income" — operating income/loss line OR "Income from Operations" OR for financial services "Operating Income" (revenues minus operating expenses). (3) "Net Income" — net income/loss line at the bottom of the statement (final profit figure). (4) "Operating Margin" — calculate as Operating Income / Total Revenue. Search thoroughly. Do NOT return N/A — use best-effort numbers. For financial companies without gross profit, return "0" or mark as "N/A for sector".',
    },
    balance:   {
      label: 'Balance Sheet',
      prompt: 'Consolidated Balance Sheets OR Statement of Financial Position (search entire filing, look for financial statements section). NOTE: For financial services companies (brokers, exchanges, payment processors), the balance sheet may be labeled differently or use different line items. Look for: "Assets" section with total, "Liabilities" section with total, "Stockholders\' Equity" or "Members\' Equity" section with total. For brokers/exchanges: may also show "Customer segregated assets", "Cash and cash equivalents", or "Securities" instead of traditional inventory. Search for ANY table labeled as balance sheet or statement of financial position.',
      figures: 'CRITICAL: Return exactly 5 figures from the balance sheet table: (1) "Total Assets" — look for the total assets line at bottom of assets section. (2) "Current Assets" — current or liquid assets line (for financial companies: cash, customer funds, marketable securities). (3) "Total Liabilities" — total liabilities line at bottom of liabilities section. For financial companies: may include customer liabilities, payables, deposits. (4) "Current Liabilities" — current liabilities line. (5) "Shareholders Equity" — total equity/stockholders equity line (may be called "Members Equity", "Total Equity", or "Stockholders Equity"). Search thoroughly. Do NOT return N/A — use best-effort numbers. If specific lines not found, use subtotals or sections.',
    },
    cashflow:  {
      label: 'Cash Flow',
      prompt: 'Consolidated Statements of Cash Flows OR Cash Flow Statement (search entire filing in financial statements section). Look for this exact table — may be called: "Consolidated Statements of Cash Flows", "Statements of Cash Flows", "Statement of Cash Flows", "Cash Flows from Operations", or for financial companies "Statement of Cash Flow from Operations and Investing Activities". IMPORTANT: For financial services companies (brokers, exchanges, fintech), look more carefully — they may split operating activities by business line. Look for the main operating cash flow line regardless of business structure.',
      figures: 'CRITICAL — ABSOLUTELY MANDATORY: Return exactly 4 figures, ALL REQUIRED, no exceptions. (1) "Operating Cash Flow" — Look for these exact line items in order: "Net cash provided by operating activities" OR "Cash generated by operating activities" OR "Net cash flows from operating activities" OR "Net cash from operations" OR for financial companies "Operating Cash Flows" or "Cash Flows from Core Business". This is usually the FIRST major section in the cash flow statement. (2) "Capital Expenditures" — Look for "Purchases of property, plant and equipment" OR "Capital expenditures" OR "Purchases of PP&E" OR "Property and equipment purchases" OR "CapEx" OR "Technology spending" in the investing activities section. Show as negative (with minus sign). For financial companies, may be listed as infrastructure/tech investment. (3) "Stock Buybacks" — Look for "Repurchases of common stock" OR "Share repurchases" OR "Repurchase of shares" OR "Treasury stock purchases" OR "Share buyback programs" in financing activities. Show as negative if money was spent, return "0" if the line shows $0 or — or blank. (4) "Free Cash Flow" — Calculate as Operating Cash Flow minus absolute value of CapEx (ignore CapEx sign, always subtract). ALL 4 FIGURES ARE MANDATORY. Do NOT return N/A, "Not disclosed", "Not stated", or blank. If you cannot find a specific line item, look at subtotals or use nearby numbers. If absolutely impossible, return "0", but NEVER return empty.',
    },
    risks:     {
      label: 'Risk Factors',
      prompt: 'Risk Factors section (Item 1A)',
      figures: 'Find 3 risks that have a specific number (%, $, or count) that quantifies how serious the risk is. Each figure: label = short risk name (3–5 words, e.g. "Export Control Exposure", "Customer Concentration", "Debt Obligation"), value = the quantified number (e.g. "56%", "$8.4B", "3 customers"), change = "Key Risk", direction = "down" (risks are always concerning). Do NOT pick positive metrics like revenue growth or profit.',
    },
    liquidity: {
      label: 'Liquidity',
      prompt: 'Liquidity and Capital Resources section',
      figures: 'Total Cash and Marketable Securities (dollar amount, badge label "On Hand"), any revolving credit facility or commercial paper program (dollar amount, badge label "Credit Available"), and total debt or term debt (dollar amount, badge label "Total Debt"). For direction: cash is "up" if it increased, debt is "down" (higher debt is a risk), credit is "neutral".',
    },
  },
  '10-K/A': {
    amendments: {
      label: 'What Was Changed',
      prompt: 'the specific items or sections that were amended in this 10-K/A filing — which items from the original 10-K were changed or updated',
      figures: 'Extract exactly 3 figures: (1) "Items Amended" — which item numbers were changed (label = item numbers, e.g., "Item 1A, Item 7", value = count or list, badge "Items Updated", direction neutral), (2) "Amendment Type" — is this a correction, restatement, or update (label = type, value = brief reason, badge "Type", direction neutral), (3) "Filing Date" — when this amendment was filed (label = "Original vs Amendment", value = date or date range, badge "Timeline", direction neutral).',
    },
    reason: {
      label: 'Reason for Amendment',
      prompt: 'why this amendment was filed — the explanation given by the company for why the original filing needed to be corrected or updated',
      figures: 'Extract exactly 3 figures showing the reason: (1) "Primary Reason" — the main reason for amendment (label = reason type, e.g., "Correction", "Restatement", "Error", value = brief explanation, badge "Reason", direction "down" if negative correction), (2) "Issue Description" — what specifically was wrong (label = "What Was Wrong", value = description, badge "Issue", direction neutral), (3) "Correction Scope" — whether it affects financials or disclosures (label = scope type, value = which section, badge "Scope", direction neutral).',
    },
    corrections: {
      label: 'Corrected Information',
      prompt: 'the specific data, numbers, or information that was corrected or updated in this amendment — any restated financials, corrected figures, or updated disclosures',
      figures: 'Extract exactly 3 figures: (1) "Original Figure" — the original incorrect number (label = what was corrected, value = original amount, badge "Original", direction down), (2) "Corrected Figure" — the new correct number (label = what was corrected, value = corrected amount, badge "Corrected", direction up), (3) "Magnitude of Change" — the dollar or percentage difference (label = "Change Amount", value = difference, badge "Impact", direction down if material).',
    },
    business_impact: {
      label: 'Business Impact',
      prompt: 'the significance and materiality of these amendments — how important are the changes to investors and the company',
      figures: 'Extract exactly 3 figures assessing impact: (1) "Materiality" — is this material or immaterial (label = "Materiality Level", value = "Material", "Immaterial", or "Not Stated", badge "Assessment", direction "down" if material), (2) "Financial Impact" — magnitude of the correction if applicable (label = "Dollar Impact", value = amount, badge "Amount", direction "down"), (3) "Risk Impact" — whether this affects financial stability (label = "Affects", value = "Company Stability", "Financial Metrics", or "Disclosures", badge "Consequence", direction "down").',
    },
    risks: {
      label: 'Risk Changes',
      prompt: 'any changes or updates to risk factors disclosed in this amendment — did the company add, remove, or modify risk disclosures',
      figures: 'Extract risk-related figures: (1) "Risks Added" — any new risks disclosed (label = risk name, value = risk description, badge "Risk Added", direction "down"). (2) "Risks Updated" — risks that were modified (label = risk name, value = what changed, badge "Risk Updated", direction "down"). (3) "Risks Removed" — if any risks were removed (label = risk name, value = why removed, badge "Risk Removed", direction "up"). Return empty if no risk changes.',
    },
  },
  '10-Q': {
    revenue:   { label: 'Revenue',         prompt: 'Consolidated Statements of Operations — Revenue lines', figures: 'Total Net Sales or Total Revenue (dollar amount), Net Income (dollar amount), and Earnings Per Share diluted (dollar amount). Pull from the income statement table.' },
    income:    { label: 'Operating Income', prompt: 'Consolidated Statements of Operations — Profitability (search entire filing)', figures: 'CRITICAL: Return 4 figures: (1) Gross Profit, (2) Operating Income, (3) Net Income, (4) Operating Margin. Search the income statement thoroughly. Do NOT return N/A.' },
    balance:   { label: 'Balance Sheet',    prompt: 'Balance Sheet and Total Assets section',    figures: 'Total Assets (dollar amount), Cash and Equivalents (dollar amount), and Total Liabilities (dollar amount). Return exactly 4 figures including Shareholders Equity.' },
    cashflow:  { label: 'Cash Flow',        prompt: 'Consolidated Statements of Cash Flows — SEARCH ENTIRE FILING',     figures: 'CRITICAL — MANDATORY: Return exactly 4 figures, ALL REQUIRED: (1) "Operating Cash Flow" — from operating activities line. (2) "Capital Expenditures" (negative) — from "Purchases of property" or "Capital expenditures" line in investing activities. (3) "Stock Buybacks" (negative) — from "Repurchases of common stock" or "Treasury stock" line. Return "0" if buyback line shows $0. (4) "Free Cash Flow" — calculate OCF minus absolute CapEx. Return all 4. Do NOT return N/A or "Not disclosed".' },
    risks:     { label: 'Risk Factors',     prompt: 'Part II Item 1A Risk Factors',              figures: 'Find 3 risks with a specific number (%, $, or count) quantifying the risk. label = short risk name, value = the number, change = "Key Risk", direction = "down". Do NOT pick positive metrics like revenue or profit.' },
    liquidity: { label: 'Liquidity',        prompt: 'Liquidity and Capital Resources section',   figures: 'Total Cash and Marketable Securities (dollar amount, badge "On Hand"), revolving credit or commercial paper (dollar amount, badge "Credit Available"), and total debt (dollar amount, badge "Total Debt").' },
  },
  '8-K': {
    leadership:   {
      label: 'Leadership Changes',
      prompt: 'executive or board leadership changes disclosed in this filing — officer or director departures, appointments, resignations, or terminations',
      figures: 'If a leadership change is disclosed: name and new/former role (label = person\'s name, value = role, badge "Appointed" or "Departed"), effective date if stated, and any severance or compensation figure tied to the change. If this 8-K does NOT involve a leadership change, return an empty key_figures array and say so plainly in the bullets — do not invent a leadership change.',
    },
    transactions: {
      label: 'Corporate Transactions',
      prompt: 'the deal mechanics of any merger, acquisition, divestiture, asset sale, or financing transaction disclosed in this filing — who is involved, how much, and when',
      figures: 'If a transaction is disclosed: total deal or loan value (badge "Deal Value"), the counterparty, target, or lead arranger/lender name (badge "Counterparty"), and the agreement or expected closing date (badge "Effective Date"). Do NOT include interest rate tiers, pricing grids, or credit-rating brackets here — those belong in Financial Health, not here. If this 8-K does NOT involve a transaction, return an empty key_figures array and say so plainly in the bullets.',
    },
    finhealth:    {
      label: 'Financial Health',
      prompt: 'the financial cost or impact disclosed in this filing — earnings results, guidance updates, or for a financing/debt event, the actual interest cost and what it depends on',
      figures: 'If financial results are disclosed: revenue, earnings, or guidance change, each with YoY context where available. If this filing is a new loan or debt issuance instead: report each interest rate tier with the credit-rating condition spelled out directly in the label — e.g. label = "Rate at AA/Aa2 Credit Rating", value = "SOFR + 0.625%", NOT generic terms like "Category 1" or "Category 2" copied from the document. If this 8-K does NOT disclose financial results or financing costs, return an empty key_figures array and say so plainly in the bullets.',
    },
    govevents:    {
      label: 'Governance Issues',
      prompt: 'governance-related disclosures in this filing — ONLY board composition changes, bylaw or charter amendments, shareholder rights plans (poison pills), regulatory enforcement actions, investigations, or litigation/legal settlements. Routine earnings results, revenue, profit, or guidance are NOT governance — do not treat them as such even though they appear in the same filing.',
      figures: 'First decide: does this filing actually disclose one of the governance events listed above? If yes, return figures tied to it (settlement amount, fine, vote result, ownership threshold). If NO governance event is disclosed — for example if this filing is just an earnings release, product announcement, or business update — return an empty key_figures array and state plainly in the bullets that this 8-K contains no governance-related disclosures. Do not reuse financial results as governance figures.',
    },
  },
  'DEF 14A': {
    compensation: {
      label: 'Executive Pay',
      prompt: 'Summary Compensation Table showing CEO and named executive officer pay',
      figures: 'CEO total compensation (dollar amount, badge "CEO Pay", direction neutral), the second-highest paid executive total compensation (badge "2nd Highest"), and total compensation of all named executives combined if stated (badge "Total NEO Pay"). Pull exact dollar figures from the Summary Compensation Table.',
    },
    board: {
      label: 'Board',
      prompt: 'board composition, director independence, diversity, and tenure',
      figures: 'Number of independent directors (value = "X of Y directors", badge "Board Independence", direction neutral), average director tenure in years (badge "Avg Tenure"), and board size or number of committees (badge "Committees").',
    },
    proposals: {
      label: 'Shareholder Votes',
      prompt: 'shareholder proposals and items being put to a vote at the annual meeting',
      figures: 'Number of proposals on the ballot (badge "Proposals"), any stated ownership threshold for voting (badge "Vote Threshold"), and shares outstanding or quorum requirement if stated (badge "Shares Outstanding").',
    },
    governance: {
      label: 'Governance',
      prompt: 'corporate governance policies, shareholder rights, and anti-takeover provisions',
      figures: 'Any ownership percentage thresholds (badge "Ownership Threshold"), stock ownership requirements for directors or executives (badge "Director Stock Req"), and any say-on-pay vote result percentage if disclosed (badge "Say-on-Pay").',
    },
  },
  '20-F': {
    revenue:   { label: 'Revenue',         prompt: 'Extract ONLY from the Consolidated Statements of Operations/Income Statement section (look for the table with line items and dollar amounts). Focus on: total revenue, net revenues, or turnover figures. EXCLUDE auditor opinions, attestations, or management discussion sections. Provide the actual financial figures with growth trends and year-over-year comparisons. Note: some foreign companies use "Revenue", "Turnover", or "Net revenue" — accept any of these.', figures: 'Total Revenue or Turnover (dollar or euro amount in billions), Net Income or Profit for the period (dollar/euro amount in billions), and Basic or Diluted EPS (per share amount). ONLY pull from the numerical income statement table, not narrative text.' },
    income:    { label: 'Operating Income', prompt: 'Extract ONLY from the Consolidated Statements of Operations/Income Statement numerical tables. Focus on: gross profit, operating income, operating profit, or EBIT line items. EXCLUDE auditor opinions, attestations, internal control discussions, or management commentary. Provide the actual financial figures with profitability trends and comparisons to prior periods.', figures: 'Gross Profit (dollar/euro amount in billions), Operating Income or Operating Profit (dollar/euro amount in billions), and R&D or SG&A expense (dollar/euro amount in billions). ONLY pull from the numerical income statement table, not from audit or attestation sections.' },
    risks:     { label: 'Risk Factors',    prompt: 'Risk Factors section including country, currency, and regulatory risks', figures: 'Find 3 risks with a specific number (%, $, or count). label = short risk name, value = the number, change = "Key Risk", direction = "down".' },
    balance:   { label: 'Balance Sheet',   prompt: 'Consolidated Balance Sheets or Statement of Financial Position', figures: 'Return 4 figures: Total Assets, Cash and Equivalents, Total Liabilities, and Shareholders Equity or Total Equity. Pull from the balance sheet table.' },
    cashflow:  { label: 'Cash Flow',       prompt: 'Consolidated Statements of Cash Flows', figures: 'Return 4 figures: Operating Cash Flow, Capital Expenditures (negative), any buybacks or dividends paid (negative), and Free Cash Flow.' },
    liquidity: { label: 'Liquidity',       prompt: 'Liquidity and Capital Resources section', figures: 'Cash and equivalents (badge "On Hand"), credit facilities or revolving credit (badge "Credit Available"), and total debt or borrowings (badge "Total Debt").' },
  },
  '13-F': {
    holdings:  {
      label: 'Top Holdings',
      prompt: 'the list of stock holdings sorted by market value',
      figures: 'The single largest position by value (label = company name, value = dollar amount, badge "Largest Position", direction neutral), total portfolio value (badge "Portfolio Value"), and number of positions (badge "# Positions").',
    },
    changes:   {
      label: 'Portfolio Changes',
      prompt: 'the quarter-over-quarter changes to this manager\'s portfolio — new positions, exited positions, and increased or decreased stakes, compared against the prior quarter\'s 13-F filing',
      figures: 'Using ONLY the real data provided (do not invent figures): the largest brand-new position added this quarter (label = company name, value = dollar amount, badge "New Position", direction "up"), the largest position fully exited (label = company name, value = the dollar amount it was worth, badge "Exited", direction "down"), and the largest dollar increase to an existing stake (label = company name, value = the dollar increase, badge "Increased Stake", direction "up"). If a category has no entries, omit it and use the next-most relevant figure instead.',
    },
    overview:  {
      label: 'Overview',
      prompt: 'the overall portfolio summary including total value and position count',
      figures: 'Total portfolio value (badge "AUM"), top holding concentration as % of total (badge "Top Position %"), and number of positions (badge "# Positions").',
    },
  },
};

// Fallback to 10-K sections for unknown filing types
function getSections(formType, itemKeys) {
  const sections = FILING_SECTIONS[formType] || FILING_SECTIONS['10-K'];
  if (!itemKeys) return sections;
  const filtered = Object.fromEntries(Object.entries(sections).filter(([k]) => itemKeys.includes(k)));
  return Object.keys(filtered).length ? filtered : sections;
}

// Map an 8-K's disclosed SEC Item numbers (e.g. "5.02", "2.02") to the section
// keys actually relevant to this specific filing. Item 8.01 ("Other Events") and
// 9.01 (exhibits only) are catch-alls with unpredictable content, so they fail
// open to all categories rather than risk hiding something real.
const EIGHT_K_ITEM_MAP = {
  '5.01': 'leadership', '5.02': 'leadership',
  '1.01': 'transactions', '1.02': 'transactions', '2.01': 'transactions', '2.05': 'transactions', '2.06': 'transactions',
  '2.02': 'finhealth', '2.03': 'finhealth', '2.04': 'finhealth', '7.01': 'finhealth',
  '3.01': 'govevents', '3.02': 'govevents', '3.03': 'govevents', '4.01': 'govevents', '4.02': 'govevents', '5.03': 'govevents', '5.07': 'govevents', '1.03': 'govevents',
};
const ALL_8K_KEYS = ['leadership', 'transactions', 'finhealth', 'govevents'];

function parse8KItemCodes(idxHtml) {
  const m = /<div class="infoHead">Items<\/div>\s*<div class="info">([\s\S]*?)<\/div>/i.exec(idxHtml);
  if (!m) return [];
  return [...m[1].matchAll(/Item\s+(\d\.\d{2})/gi)].map(x => x[1]);
}

function categorize8KItems(itemCodes) {
  const cats = new Set();
  let wildcard = false;
  for (const code of itemCodes) {
    // 9.01 (Financial Statements and Exhibits) is just the exhibit list attached to
    // nearly every 8-K — it carries no topic signal, so it's ignored rather than
    // treated as ambiguous. Only 8.01 ("Other Events") is a genuine catch-all.
    if (code === '9.01') continue;
    if (code === '8.01') { wildcard = true; continue; }
    if (EIGHT_K_ITEM_MAP[code]) cats.add(EIGHT_K_ITEM_MAP[code]);
  }
  if (wildcard || cats.size === 0) return ALL_8K_KEYS; // fail open when ambiguous
  return [...cats];
}

// Keep a flat SECTIONS reference for backward compat
const SECTIONS = FILING_SECTIONS['10-K'];

// Find the absolute position of a major SEC item header in the document,
// skipping any TOC occurrences (which end with a page number on the same line).
function findItemPos(text, tocSkip, pattern) {
  const body = text.substring(tocSkip);
  let searchFrom = 0;
  let match;
  while ((match = pattern.exec(body.substring(searchFrom))) !== null) {
    const localIdx = searchFrom + match.index;
    const lineEnd = body.indexOf('\n', localIdx + match[0].length);
    const line = body.substring(localIdx, lineEnd > 0 ? lineEnd : localIdx + 120);
    if (!/\s\d{1,3}\s*$/.test(line.trim())) {
      return tocSkip + localIdx;
    }
    searchFrom = localIdx + 1;
  }
  return null;
}

// Search for pattern within a bounded slice of text. Returns an excerpt or null.
function searchWithin(text, start, end, pattern, excerptSize = 5000) {
  if (start == null) return null;
  const limit = end ? Math.min(end, start + 100000) : start + 100000;
  const chunk = text.substring(start, limit);
  const match = pattern.exec(chunk);
  if (!match) return null;
  const absStart = start + Math.max(0, match.index - 150);
  return text.substring(absStart, Math.min(text.length, absStart + excerptSize));
}

// Scan the full filing text for keyword labels and return a compact block of
// label + nearby numbers for Claude to read. Works whether EDGAR puts numbers
// on the same line as the label or on the lines immediately below.
function extractLineItems(text, keywords, tocSkip) {
  const skipChars = tocSkip || Math.floor(text.length * 0.12);
  const body = text.substring(skipChars);
  const results = [];
  const seen = new Set();
  const hasNumber = /\b\d{2,3},\d{3}\b/; // 6-digit number like 416,161

  for (const kw of keywords) {
    const src = kw.source.replace(/^\^/, '').replace(/\$$/, '');
    const loose = new RegExp(src, 'ig');
    let match;
    while ((match = loose.exec(body)) !== null) {
      const start = Math.max(0, match.index - 10);
      const snippet = body.substring(start, start + 400).trim();
      // Skip narrative mentions — only keep lines that have an actual dollar figure nearby
      if (!hasNumber.test(snippet)) continue;
      const key = snippet.substring(0, 40);
      if (!seen.has(key)) {
        seen.add(key);
        results.push(snippet);
      }
      if (results.length >= 20) break;
    }
    if (results.length >= 20) break;
  }
  console.log(`[extractLineItems] matched ${results.length} items, first: ${results[0]?.substring(0,120).replace(/\n/g,'|')}`);
  return results.length ? results.join('\n\n') : null;
}

// Extract and validate revenue from statement text
// Handles multiple formats: "Total Revenues: $123,456" or "Revenues 123456"
function extractRevenueValue(text) {
  // Patterns to match revenue values (in millions or thousands)
  const patterns = [
    // "Total Revenues: $245,100" or "Total revenues 245,100"
    /(?:total\s+)?(?:net\s+)?revenues?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?\s*(?:million|thousand)?/i,
    // "Revenues: $245,100 (in millions)"
    /revenues?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?\s*(?:in\s+)?(?:millions?|thousands?)?/i,
    // Year format "2024: $245,100"
    /(?:fiscal\s+)?(?:year\s+)?20\d{2}[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
    // Sales format
    /sales[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?\s*(?:in\s+)?(?:millions?|thousands?)?/i
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) {
      const value = match[1].replace(/,/g, '');
      const numValue = parseFloat(value);

      // Validate: revenue should be positive and reasonable magnitude
      if (numValue > 0 && numValue < 1000000) { // Less than 1 million millions
        console.log(`[extractRevenueValue] Extracted: $${value} (matches pattern: ${pattern.source})`);
        return { value: numValue, raw: match[1], pattern: pattern.source };
      }
    }
  }

  return null;
}

// Universal metric extraction with pattern matching
// Handles all financial metrics across all filing types
function extractFinancialMetric(text, metricName) {
  const metrics = {
    'gross_profit': {
      patterns: [
        /(?:gross\s+)?profit[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /cost\s+of\s+(?:revenues?|goods?\s+sold)[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /gross\s+margin[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'operating_income': {
      patterns: [
        /(?:operating\s+)?income[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /(?:loss|income)\s+from\s+operations[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /operating\s+(?:profit|loss)[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /ebit[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: -1000000,
      maxValue: 1000000,
      unit: 'millions'
    },
    'net_income': {
      patterns: [
        /(?:net\s+)?income[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /(?:net\s+)?earnings?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /profit\s+(?:for\s+the\s+)?(?:period|year)[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /attributable\s+to\s+(?:shareholders|parent)[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: -1000000,
      maxValue: 1000000,
      unit: 'millions'
    },
    'operating_cash_flow': {
      patterns: [
        /(?:net\s+)?cash\s+(?:provided\s+by|generated\s+by|from|used\s+in)?\s*operating\s+activities[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /cash\s+flows?\s+from\s+(?:continuing\s+)?operations?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /operating\s+cash\s+flow[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /ocf[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: -1000000,
      maxValue: 1000000,
      unit: 'millions'
    },
    'capital_expenditure': {
      patterns: [
        /(?:capital\s+)?expenditures?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /(?:purchases?\s+of|acquisition\s+of)\s+(?:property|equipment|ppe)[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /capex[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /cash\s+(?:used\s+in|for)\s+investing\s+activities[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'free_cash_flow': {
      patterns: [
        /(?:free\s+)?cash\s+flow[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /fcf[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /operating\s+(?:cash\s+)?flow\s+(?:minus|-)\s*capex[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: -1000000,
      maxValue: 1000000,
      unit: 'millions'
    },
    'total_assets': {
      patterns: [
        /(?:total\s+)?assets[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /total\s+(?:current\s+and\s+)?assets?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /assets[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'total_liabilities': {
      patterns: [
        /(?:total\s+)?liabilities?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /total\s+(?:current\s+and\s+)?liabilities?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'stockholder_equity': {
      patterns: [
        /(?:total\s+)?stockholders?[\s\']?\s*equity[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /(?:total\s+)?shareholders?[\s\']?\s*equity[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /total\s+equity[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /owners?[\s\']?\s*equity[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: -1000000,
      maxValue: 1000000,
      unit: 'millions'
    },
    'current_assets': {
      patterns: [
        /(?:total\s+)?current\s+assets[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /current\s+assets[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'current_liabilities': {
      patterns: [
        /(?:total\s+)?current\s+liabilities?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i,
        /current\s+liabilities?[\s:=]*\$?\s*\(?([0-9,]+(?:\.[0-9]+)?)\)?/i
      ],
      minValue: 0,
      maxValue: 1000000,
      unit: 'millions'
    },
    'eps_diluted': {
      patterns: [
        /(?:diluted\s+)?(?:earnings?\s+)?per\s+share[\s:=]*\$?\s*([0-9,]+(?:\.[0-9]+)?)/i,
        /diluted\s+eps[\s:=]*\$?\s*([0-9,]+(?:\.[0-9]+)?)/i,
        /eps[\s:=]*\$?\s*([0-9,]+(?:\.[0-9]+)?)/i
      ],
      minValue: -1000,
      maxValue: 1000,
      unit: 'per_share'
    }
  };

  const metricConfig = metrics[metricName];
  if (!metricConfig) {
    console.log(`[extractFinancialMetric] Unknown metric: ${metricName}`);
    return null;
  }

  for (const pattern of metricConfig.patterns) {
    const match = pattern.exec(text);
    if (match) {
      const value = match[1].replace(/,/g, '');
      const numValue = parseFloat(value);

      if (numValue >= metricConfig.minValue && numValue <= metricConfig.maxValue) {
        console.log(`[extractFinancialMetric] ${metricName}: $${value} (unit: ${metricConfig.unit})`);
        return { value: numValue, raw: match[1], metric: metricName, unit: metricConfig.unit };
      }
    }
  }

  console.log(`[extractFinancialMetric] No valid match for ${metricName}`);
  return null;
}

// Detect filing type from text or metadata
function detectFilingType(text, formType) {
  const typeMap = {
    '10-K': 'annual',
    '10-Q': 'quarterly',
    '8-K': 'current_report',
    '20-F': 'international_annual',
    '20-Q': 'international_quarterly',
    'DEF 14A': 'proxy',
    'S-1': 'registration',
    'S-4': 'merger_registration',
    '424B5': 'prospectus'
  };

  if (typeMap[formType]) return typeMap[formType];

  // Fallback: detect from text
  if (text.match(/quarterly report/i)) return 'quarterly';
  if (text.match(/annual report/i)) return 'annual';
  if (text.match(/current report/i)) return 'current_report';
  if (text.match(/proxy statement/i)) return 'proxy';

  return 'unknown';
}

// Get filing-type-specific metrics
function getMetricsForFilingType(filingType) {
  const filingMetrics = {
    'annual': ['revenue', 'gross_profit', 'operating_income', 'net_income', 'operating_cash_flow', 'capital_expenditure', 'total_assets', 'stockholder_equity', 'eps_diluted'],
    'quarterly': ['revenue', 'operating_income', 'net_income', 'operating_cash_flow', 'eps_diluted'],
    'international_annual': ['revenue', 'gross_profit', 'operating_income', 'net_income', 'operating_cash_flow', 'total_assets', 'stockholder_equity'],
    'international_quarterly': ['revenue', 'operating_income', 'net_income', 'operating_cash_flow'],
    'current_report': ['revenue', 'net_income'], // Limited data in 8-K
    'proxy': [], // No financial metrics in proxy
    'registration': ['revenue', 'net_income'], // Varies by company stage
  };

  return filingMetrics[filingType] || [];
}

// Search for financial statement keywords throughout the entire text
// Enhanced to work across all filing types and statement sections
function findFinancialStatementSection(text, keyword, filingType = 'annual') {
  let allMatches = [];
  const searchPattern = new RegExp(keyword, 'gi');
  let match;

  // Find ALL occurrences of the keyword to locate the actual table (not narrative mentions)
  while ((match = searchPattern.exec(text)) !== null) {
    allMatches.push(match.index);
  }

  if (allMatches.length === 0) return null;

  // Special handling for balance sheet across all filing types
  if (keyword.includes('balance')) {
    // For 10-Q (quarterly), look for similar patterns as 10-K
    const patterns = [
      /total\s+assets[:\s]*=?\s*\$?[\d,]+/i,
      /current\s+assets[:\s]*=?\s*\$?[\d,]+/i,
      /total\s+stockholders?[\s\']?equity[:\s]*=?\s*\$?[\d,]+/i,
      /total\s+liabilities?[:\s]*=?\s*\$?[\d,]+/i
    ];

    for (const startPos of allMatches) {
      const chunk = text.substring(startPos, Math.min(startPos + 50000, text.length));

      // Try all balance sheet patterns
      let foundPattern = null;
      for (const pattern of patterns) {
        const m = pattern.exec(chunk);
        if (m) {
          foundPattern = m;
          break;
        }
      }

      if (foundPattern) {
        // Go back to capture full table
        const tableStart = Math.max(0, startPos + foundPattern.index - 1000);
        const excerpt = text.substring(tableStart, tableStart + 40000);
        console.log(`[findFinancialStatement] Found balance sheet at position ${tableStart} (${filingType})`);
        return excerpt;
      }
    }
  }

  // Special handling for cash flow statements - works across all filing types
  if (keyword.includes('cash')) {
    const patterns = [
      /(?:net\s+)?cash\s+(?:provided\s+by|generated\s+by|from|used\s+in)?\s*operating\s+activities[:\s]*=?\s*\$?[\d,]+/i,
      /cash\s+flows?\s+from\s+(?:continuing\s+)?operations?[:\s]*=?\s*\$?[\d,]+/i,
      /(?:net\s+)?cash\s+used\s+in\s+(?:continuing\s+)?investing\s+activities[:\s]*=?\s*\$?[\d,]+/i,
      /operating\s+cash\s+flow[:\s]*=?\s*\$?[\d,]+/i
    ];

    for (const startPos of allMatches) {
      const chunk = text.substring(startPos, Math.min(startPos + 50000, text.length));

      let foundPattern = null;
      for (const pattern of patterns) {
        const m = pattern.exec(chunk);
        if (m) {
          foundPattern = m;
          break;
        }
      }

      if (foundPattern) {
        const tableStart = Math.max(0, startPos + foundPattern.index - 1500);
        const excerpt = text.substring(tableStart, tableStart + 45000);
        console.log(`[findFinancialStatement] Found cash flow statement at position ${tableStart} (${filingType})`);
        return excerpt;
      }
    }
  }

  // Special handling for income/revenue statements: search for actual revenue line with numbers
  if (keyword.includes('earnings') || keyword.includes('income')) {
    // Multiple revenue patterns to handle different formats
    const revenuePatterns = [
      // Standard formats: "Total revenues", "Net revenues", etc.
      /(?:total\s+)?(?:net\s+)?revenues?[:\s]*=?\s*\$?[\(\[]?[\d,\.]+/i,
      // Alternative: "Sales" or "Product/Service revenues"
      /(?:product|service)?\s*(?:revenues?|sales)[:\s]*=?\s*\$?[\(\[]?[\d,\.]+/i,
      // Consolidated statements header patterns (look for first income line)
      /(?:in\s+)?(?:thousands?|millions?)?[,\s]*\n\s*(?:product|service|total|net)?\s*(?:revenues?|sales)[:\s]*=?\s*\$?[\(\[]?[\d,\.]+/i,
      // Year-to-year format (common in tables)
      /(?:fiscal\s+)?20\d{2}[:\s]+\$?[\d,\.]+|[A-Za-z]+\s+20\d{2}[:\s]+\$?[\d,\.]+/i
    ];

    const incomePattern = /(?:gross\s+)?profit|operating\s+income|net\s+income[:\s]*=?\s*\$?[\(\-]?[\d,\.]+/i;

    for (const startPos of allMatches) {
      // Search within the next 50k chars for actual table numbers
      const chunk = text.substring(startPos, Math.min(startPos + 50000, text.length));

      let bestMatch = null;
      let bestMatchIndex = Infinity;

      // Try each revenue pattern
      for (const pattern of revenuePatterns) {
        const m = pattern.exec(chunk);
        if (m && m.index < bestMatchIndex) {
          bestMatch = m;
          bestMatchIndex = m.index;
        }
      }

      const incomeMatch = incomePattern.exec(chunk);

      if (bestMatch || incomeMatch) {
        // Found actual line items with numbers - go back to catch the full statement
        const lineStart = bestMatch?.index ?? incomeMatch?.index;
        const tableStart = Math.max(0, startPos + lineStart - 3000);
        const excerpt = text.substring(tableStart, tableStart + 45000);
        console.log(`[findFinancialStatement] Found income statement with revenue data at position ${tableStart}`);
        return excerpt;
      }
    }
  }

  // Special handling for cash flow: search for actual operating activities line with numbers
  if (keyword.includes('cash')) {
    // Look for "Operating Activities" or "Net cash from operating" with actual dollar amounts
    const operatingPattern = /(?:net\s+)?cash\s+(?:provided\s+by|generated\s+by|from|used\s+in)?\s*operating\s+activities[:\s]+[\(\$\-]?[\d,\.]+/i;
    const investingPattern = /cash\s+(?:used\s+in|from)\s+investing[:\s]+[\(\$\-]?[\d,\.]+/i;

    for (const startPos of allMatches) {
      // Search within the next 50k chars for actual table numbers
      const chunk = text.substring(startPos, Math.min(startPos + 50000, text.length));

      const operatingMatch = operatingPattern.exec(chunk);
      const investingMatch = investingPattern.exec(chunk);

      if (operatingMatch || investingMatch) {
        // Found actual line items with numbers - go back to catch the full statement
        const lineStart = operatingMatch?.index || investingMatch?.index;
        const tableStart = Math.max(0, startPos + lineStart - 1000);
        const excerpt = text.substring(tableStart, tableStart + 35000);
        console.log(`[findFinancialStatement] Found cash flow statement with actual numbers at position ${tableStart}`);
        return excerpt;
      }
    }
  }

  // For sections without special handling: use the last significant match (likely the actual statement, not TOC)
  const lastPos = allMatches[allMatches.length - 1];
  const excerpt = text.substring(lastPos, lastPos + 30000);
  console.log(`[findFinancialStatement] Found "${keyword}" at position ${lastPos}, extracted ${excerpt.length} chars`);
  return excerpt;
}

function extractSection(text, key, toc) {
  const tocSkip = Math.floor(text.length * 0.12);

  // If TOC provided with page numbers, use them to estimate text positions
  // This helps find financial statements that are deep in the document
  if (toc) {
    if (key === 'balance' && toc.balance) {
      const pos = estimateCharPositionFromPage(toc.balance);
      console.log(`[extractSection] Using TOC: balance at page ${toc.balance} (est. char ${pos})`);
      const section = findFinancialStatementSection(text, 'consolidated\\s+balance\\s+sheets?');
      if (section) return section;
    }
    if ((key === 'revenue' || key === 'income') && toc.income) {
      const pos = estimateCharPositionFromPage(toc.income);
      console.log(`[extractSection] Using TOC: income at page ${toc.income} (est. char ${pos})`);
      const section = findFinancialStatementSection(text, 'consolidated\\s+statements?\\s+of\\s+(?:earnings|income)');
      if (section) return section;
    }
    if (key === 'cashflow' && toc.cashflow) {
      const pos = estimateCharPositionFromPage(toc.cashflow);
      console.log(`[extractSection] Using TOC: cashflow at page ${toc.cashflow} (est. char ${pos})`);
      // Try multiple variations of cash flow statement titles
      let section = findFinancialStatementSection(text, 'consolidated\\s+statements?\\s+of\\s+cash\\s+flows?');
      if (!section) section = findFinancialStatementSection(text, 'statements?\\s+of\\s+cash\\s+flows?');
      if (!section) section = findFinancialStatementSection(text, 'cash\\s+flows?\\s+(?:statement|from)?');
      if (section) return section;
    }
  }

  // Locate major SEC item boundaries — each tab lives in a specific item
  const item1a = findItemPos(text, tocSkip, /item\s+1a\.?\s*[\r\n]/i);
  const item2  = findItemPos(text, tocSkip, /item\s+2\.?\s*[\r\n]/i);
  const item7  = findItemPos(text, tocSkip, /item\s+7\.?\s*(?:management|md&a)/i);
  const item7a = findItemPos(text, tocSkip, /item\s+7a\.?\s*quantitative/i);
  const item8  = findItemPos(text, tocSkip, /item\s+8\.?\s*financial\s+statements/i);
  const item9  = findItemPos(text, tocSkip, /item\s+9\.?\s*changes/i);

  // Boundary end of each item
  const item7End = item7a || item8;
  const item8End = item9;

  switch (key) {
    case 'risks': {
      // Find the actual Risk Factors section body — not the TOC entry.
      // A TOC entry looks like "Item 1A. Risk Factors  31" (heading + page number).
      // The real section has a paragraph of text (50+ chars) on the lines after the heading.
      const riskPattern = /item\s+1a\.?[\s\n]+risk\s+factors/ig;
      let riskPos = null;
      let rm;
      const riskBody = text.substring(tocSkip);
      while ((rm = riskPattern.exec(riskBody)) !== null) {
        const candidate = tocSkip + rm.index;
        // Skip ahead past the heading itself and check if substantive text follows
        const afterHeading = text.substring(candidate + rm[0].length, candidate + rm[0].length + 300);
        const isRealSection = afterHeading.replace(/\s+/g, ' ').trim().length > 80
          && !/^\s*\d{1,3}\s/.test(afterHeading.trim()); // not just a page number
        if (isRealSection) {
          riskPos = candidate;
        }
      }
      return (riskPos ? text.substring(riskPos, riskPos + 8000) : null)
          || (item1a ? text.substring(item1a, item1a + 8000) : null)
          || sectionFallback(text);
    }

    case 'revenue':
    case 'income': {
      // First, search for consolidated income statement keyword throughout the text
      const incomeStmt = findFinancialStatementSection(text, 'consolidated\\s+statements?\\s+of\\s+(?:earnings|income)');
      if (incomeStmt) return incomeStmt;

      // Scan the filing for the specific income statement line items by keyword.
      // This is more reliable than a fixed window because EDGAR's HTML-stripped
      // tables push numbers many lines below their header.
      const incomeKeywords = [
        /(?:total\s+)?net\s+sales/i,
        /total\s+revenue/i,
        /net\s+revenue/i,
        /cost\s+of\s+(?:sales|revenue|goods\s+sold)/i,
        /gross\s+margin/i,
        /gross\s+profit/i,
        /research\s+and\s+development/i,
        /selling,?\s+general\s+and\s+administrative/i,
        /operating\s+income/i,
        /net\s+income/i,
        /diluted\s+earnings\s+per\s+share/i,
        /earnings\s+per\s+share/i,
      ];
      return extractLineItems(text, incomeKeywords, tocSkip)
          || searchWithin(text, item8, item8End, /\(In\s+millions[^)]*\)/i, 12000)
          || (item8 ? text.substring(item8, item8 + 10000) : null)
          || sectionFallback(text);
    }

    case 'balance': {
      // First, search for consolidated balance sheet keyword throughout the text
      const balanceStmt = findFinancialStatementSection(text, 'consolidated\\s+balance\\s+sheets?');
      if (balanceStmt) return balanceStmt;

      const balanceKeywords = [
        /cash\s+and\s+cash\s+equivalents/i,
        /marketable\s+securities/i,
        /accounts\s+receivable/i,
        /total\s+current\s+assets/i,
        /property,\s+plant\s+and\s+equipment/i,
        /total\s+assets/i,
        /accounts\s+payable/i,
        /total\s+current\s+liabilities/i,
        /term\s+debt/i,
        /total\s+liabilities/i,
        /total\s+(?:shareholders|stockholders)['''\s]*equity/i,
        /retained\s+earnings/i,
      ];
      return extractLineItems(text, balanceKeywords, tocSkip)
          || searchWithin(text, item8, item8End, /consolidated\s+balance\s+sheets/i, 8000)
          || sectionFallback(text);
    }

    case 'cashflow': {
      // First, search for consolidated cash flow statement keyword throughout the text
      const cashStmt = findFinancialStatementSection(text, 'consolidated\\s+statements?\\s+of\\s+cash\\s+flows?');
      if (cashStmt) return cashStmt;

      const cashKeywords = [
        /net\s+income/i,
        /depreciation\s+and\s+amortization/i,
        /share[- ]based\s+compensation/i,
        /changes\s+in\s+(?:operating|working)/i,
        /net\s+cash\s+(?:generated\s+by|provided\s+by|used\s+in)\s+operating/i,
        /purchases?\s+of\s+(?:property|equipment|marketable\s+securities)/i,
        /proceeds\s+from\s+(?:sales?\s+of|maturities)/i,
        /net\s+cash\s+(?:generated\s+by|provided\s+by|used\s+in)\s+investing/i,
        /repurchases?\s+of\s+(?:common\s+)?stock/i,
        /proceeds\s+from\s+issuance\s+of\s+(?:term\s+)?debt/i,
        /repayments?\s+of\s+term\s+debt/i,
        /dividends\s+paid/i,
        /net\s+cash\s+(?:generated\s+by|provided\s+by|used\s+in)\s+financing/i,
      ];
      return extractLineItems(text, cashKeywords, tocSkip)
          || searchWithin(text, item8, item8End, /statements?\s+of\s+cash\s+flows/i, 8000)
          || sectionFallback(text);
    }

    case 'liquidity':
      // Item 7 MD&A — Liquidity and Capital Resources subsection
      return searchWithin(text, item7, item7End, /liquidity\s+and\s+capital\s+resources/i)
          || searchWithin(text, item7, item7End, /the\s+[Cc]ompany\s+believes\s+its\s+(?:balances?\s+of\s+)?cash/i)
          || sectionFallback(text);

    // ── DEF 14A ──────────────────────────────────────────────────────────────
    case 'compensation': {
      // Find the Summary Compensation Table by scanning for executive names + dollar amounts
      const compKws = [
        /summary\s+compensation\s+table/i,
        /total\s+compensation/i,
        /(?:chief\s+executive|ceo|president)\s+(?:officer)?/i,
      ];
      return extractLineItems(text, compKws, tocSkip)
          || searchWithin(text, tocSkip, null, /summary\s+compensation\s+table/i, 8000)
          || sectionFallback(text);
    }
    case 'board': {
      const boardKws = [/independent\s+director/i, /board\s+(?:of\s+)?director/i, /director\s+tenure/i, /committee/i];
      return extractLineItems(text, boardKws, tocSkip)
          || searchWithin(text, tocSkip, null, /board\s+of\s+directors/i, 6000)
          || sectionFallback(text);
    }
    case 'proposals': {
      const propKws = [/proposal\s+\d/i, /say.on.pay/i, /annual\s+meeting/i, /shareholder\s+vote/i];
      return extractLineItems(text, propKws, tocSkip)
          || searchWithin(text, tocSkip, null, /proposal\s+\d/i, 6000)
          || sectionFallback(text);
    }
    case 'governance': {
      const govKws = [/ownership\s+(?:requirement|threshold|guideline)/i, /stock\s+ownership/i, /shareholder\s+rights/i, /say.on.pay/i];
      return extractLineItems(text, govKws, tocSkip)
          || searchWithin(text, tocSkip, null, /corporate\s+governance/i, 6000)
          || sectionFallback(text);
    }

    // ── 13-F ─────────────────────────────────────────────────────────────────
    // holdings/overview use the holdings snapshot; changes uses the prior-quarter diff
    case 'holdings':
    case 'overview':
      return text.split('===CHANGES===')[0].trim();
    case 'changes':
      return text.includes('===CHANGES===') ? text.split('===CHANGES===')[1].trim() : text;

    // ── 8-K ──────────────────────────────────────────────────────────────────
    case 'leadership':
    case 'transactions':
    case 'finhealth':
    case 'govevents':
      // 8-K exhibit text is short enough to send in full; Claude determines per-category
      // whether this specific filing actually contains that category of disclosure.
      return text.substring(0, Math.min(text.length, 15000));

    default:
      return sectionFallback(text);
  }
}

function sectionFallback(text) {
  const mid = Math.floor(text.length / 3);
  return text.substring(mid, mid + 4000);
}

function cleanSectionText(raw) {
  return raw
    .replace(/\$\s+/g, '$')           // fix "$ 416,161" → "$416,161"
    .replace(/(\d)\s+%/g, '$1%')       // fix "6 %" → "6%"
    .replace(/(\d)\s{2,}(\d)/g, '$1 $2') // collapse multiple spaces between numbers
    .replace(/\s{3,}/g, '\n')          // collapse excessive whitespace
    .trim();
}

// Claude occasionally emits an unescaped quote inside a verbatim "copy this
// sentence" string field (most common on Risk Factors quotes), which breaks
// JSON.parse. Regenerating almost always produces valid JSON on the retry,
// so this is cheaper and more reliable than trying to regex-repair the string.
async function createAndParseJSON(requestFn, label) {
  let lastErr;
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await requestFn();
    const jsonMatch = response.content[0].text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) { lastErr = new Error('Unexpected AI response format'); continue; }
    try {
      return JSON.parse(jsonMatch[0]);
    } catch (err) {
      lastErr = err;
      console.error(`[${label}] JSON parse failed (attempt ${attempt + 1}):`, err.message);
    }
  }
  throw lastErr;
}

async function analyzeSection(key, sectionText, companyName, formType, sectionPrompt, figuresHint) {
  const formSections = FILING_SECTIONS[formType] || FILING_SECTIONS['10-K'];
  const prompt = sectionPrompt || formSections[key]?.prompt || key;
  const hint = figuresHint || formSections[key]?.figures || 'Extract the 2–3 most important financial figures from this section.';
  const cleanedText = cleanSectionText(sectionText);

  // Diagnostic logging
  const textLength = cleanedText.length;
  const hasNumbers = /[\d,]+/.test(cleanedText);
  const hasCurrency = /\$|billion|million/i.test(cleanedText);
  console.log(`[${key}] ${companyName} ${formType} | length: ${textLength} | has-numbers: ${hasNumbers} | has-currency: ${hasCurrency}`);

  if (textLength < 200) {
    console.warn(`[${key}] WARNING: Text too short (${textLength} chars). Content:`, cleanedText);
  }

  // Special logging for balance sheet to debug debt vs assets
  if (key === 'balance') {
    const hasBalanceSheet = /consolidated\s+balance|total\s+assets|total\s+liabilities|stockholders.*equity/i.test(cleanedText);
    const hasDebt = /notes?\s+(?:due|payable|principal)|credit\s+facility|borrowings?|debt/i.test(cleanedText);
    console.log(`[${key}] balance sheet check: hasBalanceSheet=${hasBalanceSheet}, hasDebt=${hasDebt}`);
  }

  console.log(`[${key}] excerpt (first 400 chars):`, cleanedText.substring(0, 400).replace(/\n/g, ' | '));

  const makeRequest = () => anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 900,
    messages: [{
      role: 'user',
      content: `You are explaining a financial report to someone who isn't a financial expert. Make it simple and easy to understand.

Below is text from the ${prompt} section of ${companyName}'s ${formType}. Numbers like "$416,161" (in millions) or "6%" are real financial figures.

---
${cleanedText}
---

Return ONLY valid JSON — no markdown, no explanation, just the JSON object:
{
  "key_quote": "A key sentence from the text above",
  "key_figures": [
    { "label": "Total Revenue", "value": "$416.2B", "change": "+6%", "direction": "up", "tooltip": "All money the company earned this year" },
    { "label": "Services Revenue", "value": "$109.2B", "change": "+13%", "direction": "up", "tooltip": "Money from subscriptions and services — growing faster than products" }
  ],
  "context": "Fiscal Year 2024 ended September 28, 2024",
  "bullets": [
    "Easy-to-understand fact with specific numbers",
    "Another simple insight",
    "What this means for the company",
    "What this means for investors"
  ],
  "confidence": "high",
  "confidence_note": "Information came directly from the company's official numbers"
}

Rules — follow all of these:
- key_quote: A clear sentence that summarizes the most important point from this section. Can be from the text or rewritten to be simpler.
- context: A short date label like "Fiscal Year 2024" or "Q3 2024".
- key_figures: Include 2–4 numbers (${hint}). Each should have:
  * label: A simple name (e.g. "Total Revenue", "Operating Margin", "Cash on Hand")
  * value: The number formatted nicely (e.g. "$416.2B", "31.5%", "1.2M users")
  * change: How it changed (e.g. "+6%", "-2%", or "Growing", "Declining")
  * direction: "up" for good news, "down" for bad news, "neutral" for informational
  * tooltip: One short sentence (under 90 chars) explaining what this means in plain English
- bullets: 4 simple insights anyone can understand. Include specific numbers. Write them so a high school student would get it.
- confidence: Your honest assessment:
  * "high" — the data came clearly from official financial statements
  * "medium" — some numbers had to be pieced together from different parts
  * "low" — the section didn't have clear information for this topic
- confidence_note: One short phrase explaining your confidence level.
- CRITICAL: This entire response must be valid JSON. If any quoted string contains a double-quote character, escape it as \\" .`,
    }],
  });

  const parsed = await createAndParseJSON(makeRequest, key);
  console.log(`[${key}] key_quote:`, parsed.key_quote?.substring(0, 80));
  console.log(`[${key}] key_figures:`, JSON.stringify(parsed.key_figures));
  return parsed;
}

async function generateTakeaways(text, companyName, formType) {
  const makeRequest = () => anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 800,
    messages: [{
      role: 'user',
      content: `You are explaining a financial report to someone who isn't a financial expert. Make it simple and easy to understand.

Based on this ${formType} from ${companyName}, provide exactly 6 simple, clear takeaways. What should someone know about this company after reading its financial report?

Text:
---
${text.substring(0, 8000)}
---

Return ONLY valid JSON:
{
  "takeaways": [
    "Simple fact about the company with specific numbers",
    "Another important point with numbers",
    "What's going well for this company",
    "What might be a challenge or concern",
    "How the company is spending money",
    "What this means for the company's future"
  ]
}

Rules for each takeaway:
- Write it so anyone can understand it — no finance jargon
- Include specific numbers (like "$2.5B" or "15% growth") when possible
- Focus on facts that matter: Is the company making money? Growing? Having problems?
- Be honest about both good news and bad news`,
    }],
  });

  return createAndParseJSON(makeRequest, 'takeaways');
}


// `onlyKeys`, when provided, restricts which sections actually get analyzed by
// Claude (used for the locked-filing-type preview, which only analyzes one
// section to keep cost low) — but sectionLabels is always built from the FULL
// section set, so the tab bar can still show every tab name, locked or not.
async function runFullAnalysis(text, companyName, formType, itemKeys, onlyKeys, toc) {
  const sections = getSections(formType, itemKeys);
  const keysToAnalyze = onlyKeys || Object.keys(sections);
  const sectionTexts = {};
  keysToAnalyze.forEach(key => {
    sectionTexts[key] = extractSection(text, key, toc);
  });

  const [sectionResults, takeawaysResult] = await Promise.all([
    Promise.all(
      keysToAnalyze.map(key =>
        analyzeSection(key, sectionTexts[key], companyName, formType, sections[key].prompt, sections[key].figures)
          .then(result => [key, result])
          .catch(err => [key, { key_quote: '', key_figures: [], bullets: [`Analysis error: ${err.message}`], confidence: 'low', confidence_note: 'Analysis failed for this section' }])
      )
    ),
    generateTakeaways(text, companyName, formType),
  ]);

  return {
    sections: Object.fromEntries(sectionResults),
    sectionLabels: Object.fromEntries(Object.entries(sections).map(([k, v]) => [k, v.label])),
    takeaways: takeawaysResult.takeaways,
  };
}

// ── ANALYZE ROUTES ────────────────────────────────────────────────────────────

// Streaming analysis endpoint using Server-Sent Events
app.post('/api/analyze/edgar', authMiddleware, async (req, res) => {
  const startTime = Date.now();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendEvent = (type, data) => {
    res.write(`event: ${type}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  const sendError = (message) => {
    sendEvent('error', { error: message });
    res.end();
  };

  try {
    const { ticker, accessionNumber, primaryDocument, formType, companyName } = req.body;
    if (!ticker || !accessionNumber || !primaryDocument) {
      return sendError('Missing required fields: ticker, accessionNumber, primaryDocument');
    }
    if (!process.env.ANTHROPIC_API_KEY) {
      return sendError('ANTHROPIC_API_KEY is not configured on the server.');
    }

    const access = await checkTierAccess(req.user.id, formType);
    if (!access.allowed) {
      const messages = {
        USAGE_CAP_REACHED: `You've used all ${access.error.limit} free analyses this month. Upgrade to Pro for unlimited analyses.`,
        USER_NOT_FOUND: 'Account not found. Please sign in again.',
      };
      return sendError(messages[access.error.code] || 'Upgrade to Pro to continue.');
    }
    const isPro = isEffectivelyPro(access.user);

    // Check cache for recent analysis of this filing
    const cacheKey = `${ticker.toUpperCase()}:${accessionNumber}:${formType}`;
    const cachedResult = analysisCache.get(cacheKey);
    if (cachedResult && Date.now() - cachedResult.timestamp < CACHE_TTL) {
      console.log(`[analyze] Cache hit for ${cacheKey} (served in ${Date.now() - startTime}ms)`);
      sendEvent('complete', cachedResult.result);
      res.end();
      return;
    }

    let t1 = Date.now();
    const { cik } = await getCompanyCIK(ticker);
    const { text, sourceUrl, toc } = await fetchFilingText(cik, accessionNumber, primaryDocument, formType);
    console.log(`[analyze] Filing fetch completed in ${Date.now() - t1}ms`);

    sendEvent('loading', { status: 'fetching_filing', progress: 20 });

    let itemKeys;
    if (formType === '8-K') {
      try {
        const idxHtml = await fetchFilingIndex(cik, accessionNumber);
        itemKeys = categorize8KItems(parse8KItemCodes(idxHtml));
      } catch (err) {
        console.error('8-K item parsing failed, showing all categories:', err.message);
      }
    }

    // Locked filing types get a one-section preview instead of full access —
    // real teaser content, not a fake/blurred copy, but cheap to generate.
    const allKeys = Object.keys(getSections(formType, itemKeys));
    const onlyKeys = access.preview ? [allKeys[0]] : undefined;

    // Fetch XBRL in parallel with AI analysis for 10-K, 10-Q, and 20-F
    const xbrlSupportedForms = ['10-K', '10-Q', '20-F'];
    const shouldFetchXBRL = xbrlSupportedForms.includes(formType) && cik && accessionNumber;

    sendEvent('loading', { status: 'analyzing_sections', progress: 40 });

    let t2 = Date.now();
    const [{ sections, sectionLabels, takeaways }, xbrlMetrics] = await Promise.all([
      runFullAnalysis(text, companyName, formType, itemKeys, onlyKeys, toc),
      shouldFetchXBRL ? fetchXBRLMetricsAsync(cik, accessionNumber, formType) : Promise.resolve(null)
    ]);
    console.log(`[analyze] AI analysis + XBRL fetch completed in ${Date.now() - t2}ms`);

    sendEvent('loading', { status: 'processing_metrics', progress: 80 });

    // Update key_figures with XBRL data after analysis completes
    if (xbrlMetrics) {
      updateSectionsWithXBRLData(sections, xbrlMetrics);
      console.log(`[analyze] XBRL data integrated for ${formType}`);
    }
    await incrementUsage(req.user.id);

    const lockedSections = allKeys.filter(k => !(k in sections));

    // Truncate long-form text for non-Pro users so there's something genuine
    // to preview but a clear incentive to upgrade for the rest. The single
    // preview section for a fully-locked filing type is left untouched —
    // it's meant to look like a complete, convincing sample on its own.
    let responseTakeaways = takeaways;
    const takeawaysTotal = takeaways.length;
    if (!isPro) {
      responseTakeaways = takeaways.slice(0, Math.max(2, Math.ceil(takeaways.length / 2)));
    }

    let responseSections = sections;
    if (!isPro && !access.preview) {
      responseSections = Object.fromEntries(Object.entries(sections).map(([key, section]) => {
        const bullets = section.bullets || [];
        const bulletsTotal = bullets.length;
        const truncated = bullets.slice(0, Math.max(2, Math.ceil(bullets.length / 2)));
        return [key, { ...section, bullets: truncated, bulletsTotal }];
      }));
    }

    // Stream sections as they're available
    const sectionKeys = Object.keys(responseSections);
    for (const key of sectionKeys) {
      sendEvent('section', {
        key,
        data: responseSections[key],
        label: sectionLabels[key]
      });
    }

    const responseData = {
      sections: responseSections,
      sectionLabels,
      takeaways: responseTakeaways,
      takeawaysTotal,
      lockedSections,
      isPro,
      isPreview: !!access.preview,
      companyName,
      formType,
      ticker: ticker.toUpperCase(),
      sourceUrl,
      cik,
      accessionNumber,
      primaryDocument,
    };

    // Cache the result for future requests
    analysisCache.set(cacheKey, { result: responseData, timestamp: Date.now() });
    const totalTime = Date.now() - startTime;
    console.log(`[analyze] Total time for ${cacheKey}: ${totalTime}ms (cached for future requests)`);

    // Send completion event with metadata
    sendEvent('complete', {
      sectionLabels,
      takeaways: responseTakeaways,
      takeawaysTotal,
      lockedSections,
      isPro,
      isPreview: !!access.preview,
      companyName,
      formType,
      ticker: ticker.toUpperCase(),
      sourceUrl,
      cik,
      accessionNumber,
      primaryDocument,
    });
    res.end();
  } catch (err) {
    console.error('EDGAR analysis error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── ACCOUNT ───────────────────────────────────────────────────────────────────

app.get('/api/account', authMiddleware, async (req, res) => {
  try {
    const user = await db.getUserById(req.user.id);

    // If user not found in DB, use info from JWT token
    if (!user) {
      return res.json({
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        tier: 'free',
        isPro: false,
        analysesThisMonth: 0,
        monthlyLimit: FREE_MONTHLY_LIMIT,
        hasBilling: false,
        preferences: {},
      });
    }

    const subscription = await db.getSubscriptionByUserId(req.user.id);

    // Calculate trial end date
    const trialEndsAt = subscription?.created_at ?
      new Date(new Date(subscription.created_at).getTime() + 5 * 24 * 60 * 60 * 1000).toISOString() :
      new Date(0).toISOString();

    // Check if user is in free trial (5 days from subscription creation)
    const isInTrial = subscription &&
      subscription.created_at &&
      new Date(subscription.created_at) > new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);

    const isPro = subscription?.plan_type === 'pro' || isInTrial;

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      tier: subscription?.plan_type || 'free',
      isPro: isPro,
      trialEndsAt: trialEndsAt,
      analysesThisMonth: 0,
      monthlyLimit: FREE_MONTHLY_LIMIT,
      hasBilling: !!subscription?.stripe_customer_id,
      preferences: {},
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete account endpoint
app.post('/api/account/delete', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // Delete all related data
    await Promise.all([
      db.pool.query('DELETE FROM email_verification_tokens WHERE user_id = $1', [userId]),
      db.pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]),
      db.pool.query('DELETE FROM qa_audit_log WHERE user_id = $1', [userId]),
      db.pool.query('DELETE FROM watchlist_items WHERE user_id = $1', [userId]),
      db.pool.query('DELETE FROM subscriptions WHERE user_id = $1', [userId]),
      db.pool.query('DELETE FROM users WHERE id = $1', [userId]),
    ]);

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ── USER PREFERENCES ──────────────────────────────────────────────────────────

app.post('/api/user/preferences', authMiddleware, async (req, res) => {
  try {
    const { defaultFilingType, dataRetention, theme, hasSeenTour } = req.body;
    const user = await db.getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const preferences = {
      defaultFilingType: defaultFilingType || '10-K',
      dataRetention: dataRetention || '30days',
      theme: theme || 'dark',
      hasSeenTour: hasSeenTour !== undefined ? hasSeenTour : false,
    };

    res.json({ success: true, preferences });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/2fa', authMiddleware, async (req, res) => {
  try {
    const { enabled } = req.body;
    const users = await readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });

    if (!users[idx].preferences) users[idx].preferences = {};
    users[idx].preferences.twoFactorEnabled = enabled;

    await writeJSON(USERS_FILE, users);
    res.json({ success: true, twoFactorEnabled: enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SAVED REPORTS ─────────────────────────────────────────────────────────────

app.get('/api/reports', authMiddleware, async (req, res) => {
  try {
    const reports = await readJSON(REPORTS_FILE);
    const userReports = reports
      .filter(r => r.userId === req.user.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map(({ sections, takeaways, ...meta }) => ({ ...meta, sections, takeaways }));
    res.json(userReports);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const { title, ticker, formType, sections, takeaways, filename } = req.body;
    let reports = await readJSON(REPORTS_FILE);

    // Remove duplicate: if a report with same ticker+formType already exists for this user, delete it
    if (ticker && formType) {
      reports = reports.filter(r => !(r.userId === req.user.id && r.ticker === ticker && r.formType === formType));
    }

    const report = {
      id: crypto.randomUUID(),
      userId: req.user.id,
      title: title || `${ticker || 'Report'} ${formType}`,
      ticker,
      formType,
      filename,
      sections,
      takeaways,
      createdAt: new Date().toISOString(),
    };

    reports.push(report);
    await writeJSON(REPORTS_FILE, reports);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/reports/:id', authMiddleware, async (req, res) => {
  try {
    let reports = await readJSON(REPORTS_FILE);
    const report = reports.find(r => r.id === req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (report.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    await writeJSON(REPORTS_FILE, reports.filter(r => r.id !== req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── COMPARISON SEARCH ─────────────────────────────────────────────────────
app.get('/api/reports/search', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, limit = 10 } = req.query;
    const reports = await readJSON(REPORTS_FILE);

    let filtered = reports.filter(r => r.userId === req.user.id);

    if (ticker) {
      filtered = filtered.filter(r => r.ticker.toUpperCase() === ticker.toUpperCase());
    }

    if (formType) {
      filtered = filtered.filter(r => r.formType === formType);
    }

    const results = filtered
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, parseInt(limit))
      .map(({ sections, takeaways, ...meta }) => meta);

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── COMPARISON METRICS ────────────────────────────────────────────────────
app.post('/api/comparison/metrics', authMiddleware, async (req, res) => {
  try {
    const { accessionNumber1, accessionNumber2 } = req.body;
    const reports = await readJSON(REPORTS_FILE);

    // Find both reports
    const report1 = reports.find(r =>
      r.userId === req.user.id && r.accessionNumber === accessionNumber1
    );
    const report2 = reports.find(r =>
      r.userId === req.user.id && r.accessionNumber === accessionNumber2
    );

    if (!report1 || !report2) {
      return res.status(404).json({ error: 'One or both reports not found' });
    }

    // Calculate metrics for both
    const calculateMetrics = (report) => {
      const sections = report.sections || {};
      let metrics = {};

      // Extract key metrics from sections
      if (sections.revenue) {
        const text = sections.revenue.simplified || '';
        const match = text.match(/\$[\d,]+\s*[BMT]?/);
        if (match) metrics.revenue = parseFloat(match[0].replace(/[$,]/g, ''));
      }

      if (sections.income) {
        const text = sections.income.simplified || '';
        const match = text.match(/\$[\d,]+\s*[BMT]?/);
        if (match) metrics.netIncome = parseFloat(match[0].replace(/[$,]/g, ''));
      }

      return metrics;
    };

    const metrics1 = calculateMetrics(report1);
    const metrics2 = calculateMetrics(report2);

    // Calculate diffs
    const diffs = {
      revenue: metrics2.revenue && metrics1.revenue ?
        (((metrics2.revenue - metrics1.revenue) / metrics1.revenue) * 100).toFixed(1) : null,
      netIncome: metrics2.netIncome && metrics1.netIncome ?
        (((metrics2.netIncome - metrics1.netIncome) / metrics1.netIncome) * 100).toFixed(1) : null
    };

    res.json({
      filing1: { ticker: report1.ticker, metrics: metrics1 },
      filing2: { ticker: report2.ticker, metrics: metrics2 },
      diffs
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DEEP-DIVE REPORTS ─────────────────────────────────────────────────────
app.post('/api/reports/deep-dive', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, sections, takeaways } = req.body;

    // Check tier access — Pro only (or in trial)
    const access = await checkTierAccess(req.user.id, 'deep-dive');
    if (!access.allowed) {
      return res.status(403).json({ error: 'Deep-dive reports require Pro tier' });
    }

    // Prepare section summaries and financial data for Claude
    const sectionSummaries = Object.entries(sections || {})
      .map(([key, section]) => {
        const figures = section.key_figures?.map(f => `${f.label}: ${f.value} (${f.change})`).join(', ') || '';
        return `${key.toUpperCase()}: ${section.key_quote || ''} [${figures}]`;
      })
      .join('\n\n');

    const takeawaysList = (takeaways || []).map((t, i) => `${i+1}. ${t}`).join('\n');

    // Generate deep-dive report with Claude
    const prompt = `Based on this ${formType} filing analysis for ${ticker}, create a simple, easy-to-understand report about the company's finances.

SECTIONS ANALYZED:
${sectionSummaries}

KEY TAKEAWAYS:
${takeawaysList}

Create a structured report in JSON format with these sections:
{
  "executiveSummary": "A 2-3 sentence overview: Is the company doing well financially? What's the main story?",
  "revenueInsights": "Explain in simple terms: How much money is the company making? Is it going up or down? Why?",
  "profitabilityTrends": "Explain in simple terms: Is the company making profit? Is it becoming more or less profitable? What changed?",
  "cashFlowAnalysis": "Explain in simple terms: Does the company have enough cash? Is it earning or spending more? What's its cash situation?",
  "riskAssessment": "List any problems or worries: What could go wrong for this company? What should investors watch out for?",
  "highlights": ["One good thing about this company", "Another good thing", "One more positive point"],
  "concerns": ["One problem or challenge", "Another problem or concern"],
  "outlook": "A simple 1-2 sentence prediction: Is this company likely to do better or worse in the near future based on this filing?"
}

Write everything in simple, plain English. A high school student should be able to understand it. Use specific numbers and percentages when possible.`;

    const message = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 2500,
      messages: [{ role: 'user', content: prompt }]
    });

    const responseText = message.content[0].type === 'text' ? message.content[0].text : '';

    console.log('[deep-dive] Response length:', responseText.length);
    console.log('[deep-dive] Response preview:', responseText.substring(0, 200));

    // Extract JSON from response
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    let reportData = {};
    if (jsonMatch) {
      try {
        reportData = JSON.parse(jsonMatch[0]);
        console.log('[deep-dive] Parsed report keys:', Object.keys(reportData));
      } catch (parseErr) {
        console.error('[deep-dive] JSON parse error:', parseErr.message);
        console.log('[deep-dive] JSON string:', jsonMatch[0].substring(0, 500));
      }
    } else {
      console.warn('[deep-dive] No JSON found in response');
    }

    res.json({
      ticker,
      formType,
      generatedAt: new Date().toISOString(),
      report: reportData
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ERROR FLAGGING ────────────────────────────────────────────────────────────
// Write-only for now — flags are stored for manual review, no admin UI yet.

app.post('/api/flags', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, accessionNumber, sectionKey, sectionLabel, reason } = req.body;
    if (!reason || !reason.trim()) return res.status(400).json({ error: 'Please describe what looks wrong.' });
    if (reason.length > 500) return res.status(400).json({ error: 'Please keep your description under 500 characters.' });

    const flags = await readJSON(FLAGS_FILE);
    const flag = {
      id: crypto.randomUUID(),
      userId: req.user.id,
      userEmail: req.user.email,
      ticker,
      formType,
      accessionNumber,
      sectionKey,
      sectionLabel,
      reason: reason.trim(),
      createdAt: new Date().toISOString(),
      status: 'open',
    };
    flags.push(flag);
    await writeJSON(FLAGS_FILE, flags);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ANNOTATIONS ────────────────────────────────────────────────────────────────

app.post('/api/annotations', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, accessionNumber, sectionKey, sectionLabel, text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please add some text.' });
    if (text.length > 1000) return res.status(400).json({ error: 'Annotation must be under 1000 characters.' });

    const annotations = await readJSON(ANNOTATIONS_FILE);
    const annotation = {
      id: crypto.randomUUID(),
      userId: req.user.id,
      ticker,
      formType,
      accessionNumber,
      sectionKey,
      sectionLabel,
      text: text.trim(),
      createdAt: new Date().toISOString(),
    };
    annotations.push(annotation);
    await writeJSON(ANNOTATIONS_FILE, annotations);
    res.json(annotation);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/annotations', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, accessionNumber } = req.query;
    const annotations = await readJSON(ANNOTATIONS_FILE);
    const userAnnotations = annotations.filter(a =>
      a.userId === req.user.id &&
      a.ticker === ticker &&
      a.formType === formType &&
      a.accessionNumber === accessionNumber
    );
    res.json(userAnnotations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/annotations/:id', authMiddleware, async (req, res) => {
  try {
    let annotations = await readJSON(ANNOTATIONS_FILE);
    const annotation = annotations.find(a => a.id === req.params.id);
    if (!annotation) return res.status(404).json({ error: 'Annotation not found' });
    if (annotation.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    await writeJSON(ANNOTATIONS_FILE, annotations.filter(a => a.id !== req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── WATCHLISTS ─────────────────────────────────────────────────────────────────

app.post('/api/watchlists/add', authMiddleware, async (req, res) => {
  try {
    const { ticker } = req.body;
    if (!ticker) return res.status(400).json({ error: 'Ticker is required.' });

    const watchlists = await readJSON(WATCHLISTS_FILE);
    let userWatchlist = watchlists.find(w => w.userId === req.user.id);

    if (!userWatchlist) {
      userWatchlist = {
        id: crypto.randomUUID(),
        userId: req.user.id,
        tickers: [],
        createdAt: new Date().toISOString(),
      };
      watchlists.push(userWatchlist);
    }

    if (!userWatchlist.tickers.includes(ticker)) {
      userWatchlist.tickers.push(ticker);
    }

    await writeJSON(WATCHLISTS_FILE, watchlists);
    res.json(userWatchlist);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/watchlists', authMiddleware, async (req, res) => {
  try {
    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };
    res.json(userWatchlist);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/watchlists/:ticker', authMiddleware, async (req, res) => {
  try {
    let watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id);
    if (!userWatchlist) return res.status(404).json({ error: 'Watchlist not found' });

    userWatchlist.tickers = userWatchlist.tickers.filter(t => t !== req.params.ticker);
    await writeJSON(WATCHLISTS_FILE, watchlists);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Enhanced watchlist with metrics, trends, and peer data
app.get('/api/watchlists/metrics', authMiddleware, async (req, res) => {
  try {
    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };

    // Retrieve latest metrics for each watched ticker
    const metricsHistory = await readJSON(METRICS_HISTORY_FILE).catch(() => []);
    const trendsData = await readJSON(TRENDS_FILE).catch(() => []);
    const alerts = await readJSON(ALERTS_FILE).catch(() => []);
    const userAlerts = alerts.filter(a => a.userId === req.user.id);

    const watchlistData = userWatchlist.tickers.map(ticker => {
      // Get most recent metrics for this ticker
      const recentMetrics = metricsHistory
        .filter(m => m.ticker.toUpperCase() === ticker.toUpperCase())
        .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate))[0];

      // Get trend status for this ticker
      const trendStatus = trendsData.find(t => t.ticker.toUpperCase() === ticker.toUpperCase());

      // Get active alerts for this ticker
      const tickerAlerts = userAlerts.filter(a => a.ticker.toUpperCase() === ticker.toUpperCase() && a.active);

      // Calculate health status badge (excellent, good, warning, critical)
      let healthStatus = 'unknown';
      if (recentMetrics && recentMetrics.healthScore) {
        const score = recentMetrics.healthScore;
        if (score >= 80) healthStatus = 'excellent';
        else if (score >= 60) healthStatus = 'good';
        else if (score >= 40) healthStatus = 'warning';
        else healthStatus = 'critical';
      }

      return {
        ticker,
        metrics: recentMetrics ? {
          revenue: recentMetrics.revenue,
          netIncome: recentMetrics.netIncome,
          operatingIncome: recentMetrics.operatingIncome,
          roa: recentMetrics.roa,
          roic: recentMetrics.roic,
          currentRatio: recentMetrics.currentRatio,
          debtToEquity: recentMetrics.debtToEquity,
          healthScore: recentMetrics.healthScore,
          filingDate: recentMetrics.filingDate,
          formType: recentMetrics.formType
        } : null,
        trends: trendStatus ? {
          improving: trendStatus.improving || 0,
          declining: trendStatus.declining || 0,
          stable: trendStatus.stable || 0
        } : null,
        healthStatus,
        alertCount: tickerAlerts.length,
        lastUpdated: recentMetrics ? recentMetrics.filingDate : null
      };
    });

    res.json({
      tickers: userWatchlist.tickers,
      data: watchlistData,
      total: userWatchlist.tickers.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Bulk peer ranking comparison for watchlist items
app.get('/api/watchlists/peer-compare', authMiddleware, async (req, res) => {
  try {
    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };

    if (!userWatchlist.tickers.length) {
      return res.json({ comparisons: [] });
    }

    const metricsHistory = await readJSON(METRICS_HISTORY_FILE).catch(() => []);

    // Get most recent metrics for each watched ticker
    const watchlistMetrics = {};
    userWatchlist.tickers.forEach(ticker => {
      const recent = metricsHistory
        .filter(m => m.ticker.toUpperCase() === ticker.toUpperCase())
        .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate))[0];
      if (recent) {
        watchlistMetrics[ticker] = recent;
      }
    });

    // Compare each ticker against its peers
    const comparisons = userWatchlist.tickers.map(ticker => {
      const peers = getPeersForCompany(ticker);
      const metrics = watchlistMetrics[ticker];

      if (!metrics) {
        return { ticker, rank: null, percentile: null, peers: [] };
      }

      // Get peer metrics
      const peerMetrics = peers.map(peerTicker => {
        const peerRecent = metricsHistory
          .filter(m => m.ticker.toUpperCase() === peerTicker.toUpperCase())
          .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate))[0];
        return { ticker: peerTicker, healthScore: peerRecent?.healthScore || 0 };
      });

      // Calculate rank and percentile for health score
      const allScores = [metrics.healthScore, ...peerMetrics.map(p => p.healthScore)];
      const sortedScores = allScores.sort((a, b) => b - a);
      const rank = sortedScores.findIndex(s => s === metrics.healthScore) + 1;
      const percentile = Math.round(((sortedScores.length - rank) / sortedScores.length) * 100);

      return {
        ticker,
        healthScore: metrics.healthScore,
        rank: `${rank}/${peers.length + 1}`,
        percentile,
        peers: peerMetrics.sort((a, b) => b.healthScore - a.healthScore)
      };
    });

    res.json({ comparisons });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Red flags summary for watchlist items
app.get('/api/watchlists/red-flags', authMiddleware, async (req, res) => {
  try {
    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };
    const flags = await readJSON(FLAGS_FILE).catch(() => []);

    if (!userWatchlist.tickers.length) {
      return res.json({ redFlags: [] });
    }

    // Get red flags for each watched ticker
    const redFlags = userWatchlist.tickers.map(ticker => {
      const tickerFlags = flags.filter(f => f.ticker.toUpperCase() === ticker.toUpperCase());
      const criticalFlags = tickerFlags.filter(f => f.severity === 'critical' || f.severity === 'high');

      return {
        ticker,
        totalFlags: tickerFlags.length,
        criticalCount: criticalFlags.length,
        flags: criticalFlags.slice(0, 3) // Top 3 critical flags
      };
    }).filter(f => f.totalFlags > 0);

    res.json({ redFlags });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Sort/filter watchlist by metrics
app.get('/api/watchlists/sorted', authMiddleware, async (req, res) => {
  try {
    const { sortBy = 'healthScore', order = 'desc', filterHealthMin = 0 } = req.query;

    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };
    const metricsHistory = await readJSON(METRICS_HISTORY_FILE).catch(() => []);

    if (!userWatchlist.tickers.length) {
      return res.json({ sorted: [] });
    }

    // Get most recent metrics for each watched ticker
    const withMetrics = userWatchlist.tickers
      .map(ticker => {
        const recent = metricsHistory
          .filter(m => m.ticker.toUpperCase() === ticker.toUpperCase())
          .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate))[0];
        return { ticker, metrics: recent };
      })
      .filter(item => item.metrics);

    // Filter by health score minimum
    const filtered = withMetrics.filter(item =>
      (item.metrics.healthScore || 0) >= parseFloat(filterHealthMin)
    );

    // Sort by selected metric
    const sorted = filtered.sort((a, b) => {
      let aVal = a.metrics[sortBy] || 0;
      let bVal = b.metrics[sortBy] || 0;

      const comparison = aVal > bVal ? 1 : -1;
      return order === 'desc' ? -comparison : comparison;
    });

    res.json({
      sorted: sorted.map(item => ({
        ticker: item.ticker,
        healthScore: item.metrics.healthScore,
        revenue: item.metrics.revenue,
        roa: item.metrics.roa,
        roic: item.metrics.roic,
        debtToEquity: item.metrics.debtToEquity,
        currentRatio: item.metrics.currentRatio,
        filingDate: item.metrics.filingDate
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Export watchlist as CSV
app.get('/api/watchlists/export/csv', authMiddleware, async (req, res) => {
  try {
    const watchlists = await readJSON(WATCHLISTS_FILE);
    const userWatchlist = watchlists.find(w => w.userId === req.user.id) || { tickers: [] };
    const metricsHistory = await readJSON(METRICS_HISTORY_FILE).catch(() => []);

    if (!userWatchlist.tickers.length) {
      return res.status(400).json({ error: 'Watchlist is empty' });
    }

    // Build CSV data
    const headers = ['Ticker', 'Health Score', 'Revenue ($M)', 'Net Income ($M)', 'ROA (%)', 'ROIC (%)', 'D/E Ratio', 'Current Ratio', 'Filing Date', 'Form Type'];
    const rows = userWatchlist.tickers.map(ticker => {
      const recent = metricsHistory
        .filter(m => m.ticker.toUpperCase() === ticker.toUpperCase())
        .sort((a, b) => new Date(b.filingDate) - new Date(a.filingDate))[0];

      if (!recent) {
        return [ticker, '—', '—', '—', '—', '—', '—', '—', '—', '—'];
      }

      return [
        ticker,
        recent.healthScore ? recent.healthScore.toFixed(1) : '—',
        recent.revenue ? (recent.revenue / 1000).toFixed(0) : '—',
        recent.netIncome ? (recent.netIncome / 1000).toFixed(0) : '—',
        recent.roa ? (recent.roa * 100).toFixed(1) : '—',
        recent.roic ? (recent.roic * 100).toFixed(1) : '—',
        recent.debtToEquity ? recent.debtToEquity.toFixed(2) : '—',
        recent.currentRatio ? recent.currentRatio.toFixed(2) : '—',
        recent.filingDate,
        recent.formType
      ];
    });

    // Generate CSV
    const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

    res.setHeader('Content-Disposition', `attachment; filename="watchlist-${new Date().toISOString().split('T')[0]}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Q&A ON FILINGS ─────────────────────────────────────────────────────────────

// Extract relevant sections from filing based on question keywords
function extractRelevantSections(filingText, question) {
  const questionLower = question.toLowerCase();
  const maxLength = 50000; // Much larger context to ensure we get the data

  let result = '';

  // Helper: Search for patterns more flexibly
  const findSection = (patterns, maxChars = 10000) => {
    for (const pattern of patterns) {
      const regex = new RegExp(pattern, 'is');
      const match = filingText.match(regex);
      if (match && match[0]) {
        return match[0].substring(0, maxChars);
      }
    }
    return null;
  };

  // Priority 1: Find financial statements with flexible patterns
  if (questionLower.match(/cash|flow|operating|investing|financing/)) {
    const cashFlowPatterns = [
      // Most flexible: title + next 25KB (covers tables with varied formatting)
      /(?:CONSOLIDATED\s+)?STATEMENTS? OF CASH FLOWS?[\s\S]{0,25000}?(?=\n\nItem |\nItem |\nCONSOLIDATED BALANCE|^$\n\n[A-Z]{2,}|$)/i,
      /Cash Flows?[\s\S]{0,500}?(?:Operating|Investing|Financing)[\s\S]{0,20000}?(?=\n\nItem|CONSOLIDATED BALANCE|$)/i,
      /Statement of Cash Flows[\s\S]{0,25000}?(?=\n\nItem|CONSOLIDATED|$)/i
    ];
    const cashSection = findSection(cashFlowPatterns, 15000);
    if (cashSection) result += 'CASH FLOW STATEMENT:\n' + cashSection + '\n\n';
  }

  if (questionLower.match(/revenue|sales|income|profit|earning|gross|operating income|net income|growth/)) {
    const incomePatterns = [
      /CONSOLIDATED STATEMENTS? OF (?:OPERATIONS?|EARNINGS?|INCOME)[\s\S]{0,500}?(?:20\d{2})[\s\S]{0,20000}?(?=\n\n[A-Z]|CONSOLIDATED BALANCE|Item|$)/i,
      /Income Statement[\s\S]{0,500}?(?:Revenue|Sales|Year)[\s\S]{0,15000}?(?=\n\n[A-Z]|Item|$)/i,
      /(?:Total Revenue|Net Revenues?|Net Sales|Products|Services)[\s\S]{0,15000}?(?=\n\nItem|\n\nCost|Gross|$)/i
    ];
    const incomeSection = findSection(incomePatterns, 15000);
    if (incomeSection) result += 'INCOME STATEMENT:\n' + incomeSection + '\n\n';
  }

  if (questionLower.match(/balance|asset|liabilit|equity|debt|debt\s|current|total|cash on hand|capital/)) {
    const balancePatterns = [
      /CONSOLIDATED BALANCE SHEETS?[\s\S]{0,500}?(?:20\d{2})[\s\S]{0,20000}?(?=\n\n[A-Z]|Item|$)/i,
      /Balance Sheet[\s\S]{0,500}?(?:ASSETS?|Total)[\s\S]{0,15000}?(?=\n\n[A-Z]|Item|$)/i,
      /ASSETS[\s\S]{0,15000}?(?=LIABILIT|Item|$)/i
    ];
    const balanceSection = findSection(balancePatterns, 15000);
    if (balanceSection) result += 'BALANCE SHEET:\n' + balanceSection + '\n\n';
  }

  // Priority 2: Find MD&A - contains management's own explanation with growth commentary
  const mdaPatterns = [
    /ITEM 7[.\s]+MANAGEMENT'S DISCUSSION AND ANALYSIS[\s\S]{0,25000}?(?=ITEM 8|Financial Statements|QUANTITATIVE|$)/i,
    /MD&A[\s\S]{0,20000}?(?=ITEM|Financial Statements|$)/i,
    /MANAGEMENT DISCUSSION[\s\S]{0,20000}?(?=ITEM 8|Results of Operations|Segment|$)/i,
    /Results of Operations[\s\S]{0,20000}?(?=Item|Liquidity|$)/i
  ];
  const mdaSection = findSection(mdaPatterns, 18000);
  if (mdaSection && result.length < 35000) {
    result += 'MANAGEMENT DISCUSSION & ANALYSIS:\n' + mdaSection + '\n\n';
  }

  // Priority 3: Business/Risk sections for other questions
  if (questionLower.match(/business|product|segment|operation/) && result.length < 35000) {
    const businessPatterns = [
      /ITEM 1[.\s]+(?:BUSINESS|OUR BUSINESS)[\s\S]{0,15000}?(?=ITEM 2|Item 1A|$)/i,
      /BUSINESS OVERVIEW[\s\S]{0,12000}?(?=Item|$)/i
    ];
    const businessSection = findSection(businessPatterns, 10000);
    if (businessSection) result += 'BUSINESS:\n' + businessSection + '\n\n';
  }

  if (questionLower.match(/risk|challenge|threat/) && result.length < 40000) {
    const riskPatterns = [
      /ITEM 1A[.\s]+RISK FACTORS?[\s\S]{0,15000}?(?=ITEM 1B|ITEM 2|$)/i,
      /RISK FACTORS?[\s\S]{0,12000}?(?=ITEM|$)/i
    ];
    const riskSection = findSection(riskPatterns, 10000);
    if (riskSection) result += 'RISK FACTORS:\n' + riskSection + '\n\n';
  }

  // If still nothing found, return substantial portion of filing
  if (!result.trim()) {
    console.log('[extractRelevantSections] No patterns matched, returning first 50KB of filing');
    result = filingText.substring(0, 50000);
  }

  return result
    .substring(0, maxLength)
    .replace(/\n\s{2,}\n/g, '\n\n') // Clean excessive line breaks
    .trim();
}

// Rate limiting per user (simple in-memory store)
const qaRateLimits = new Map();
const QA_RATE_LIMIT = 30; // questions per hour
const QA_RATE_WINDOW = 3600000; // 1 hour in ms

function checkRateLimit(userId) {
  const now = Date.now();
  const userLimit = qaRateLimits.get(userId) || { count: 0, resetTime: now + QA_RATE_WINDOW };

  if (now > userLimit.resetTime) {
    userLimit.count = 0;
    userLimit.resetTime = now + QA_RATE_WINDOW;
  }

  userLimit.count++;
  qaRateLimits.set(userId, userLimit);

  return userLimit.count <= QA_RATE_LIMIT;
}

// Validate question is on-topic (server-side)
function isQuestionOnTopic(question, ticker, companyName, formType) {
  const relevantKeywords = [
    'revenue', 'income', 'profit', 'earnings', 'cash flow', 'asset', 'liability', 'equity',
    'balance sheet', 'financial', 'statement', 'filing', 'sec', '10-k', '10-q', '8-k', '20-f',
    'quarter', 'fiscal', 'year', 'annual', 'quarterly', 'risk', 'liquidity', 'dividend',
    'margin', 'ratio', 'debt', 'loan', 'bond', 'acquisition', 'segment', 'operation',
    'business', 'strategy', 'growth', 'forecast', 'outlook', 'guidance', 'cash', 'tax',
    ticker.toLowerCase(), (companyName || '').toLowerCase(), formType.toLowerCase()
  ].filter(k => k && k.length > 0);

  const questionLower = question.toLowerCase();
  const hasRelevantKeyword = relevantKeywords.some(keyword => questionLower.includes(keyword));

  // Block obvious off-topic patterns
  const offTopicPatterns = [
    /tell me a joke/i, /weather/i, /recipe/i, /movie/i, /sports/i, /politics/i,
    /how to hack/i, /write.*code/i, /plan a trip/i, /book/i, /poem/i
  ];
  const isOffTopic = offTopicPatterns.some(pattern => pattern.test(question));

  return hasRelevantKeyword && !isOffTopic;
}

// Filter for prompt injection attempts
function detectPromptInjection(question) {
  const injectionPatterns = [
    /ignore.*previous.*instruction/i,
    /system prompt/i,
    /you are now/i,
    /pretend.*to be/i,
    /forget.*rules/i,
    /don't follow.*rules/i,
    /act as if/i,
    /new instructions/i
  ];

  return injectionPatterns.some(pattern => pattern.test(question));
}

// Audit log for QA questions
async function logQAQuestion(userId, ticker, question, isRejected, reason) {
  try {
    // Log to console for security monitoring
    const logEntry = {
      timestamp: new Date().toISOString(),
      userId,
      ticker,
      questionLength: question.length,
      isRejected,
      reason: reason || 'accepted'
    };
    console.log('[QA-AUDIT]', JSON.stringify(logEntry));
  } catch (err) {
    console.error('[QA-AUDIT-ERROR]', err.message);
  }
}

app.post('/api/qa', authMiddleware, async (req, res) => {
  try {
    const userId = req.user?.id;
    const { question, ticker, formType, accessionNumber, primaryDocument, cik } = req.body;

    if (!question?.trim()) return res.status(400).json({ error: 'Please ask a question.' });
    if (!ticker || !formType) return res.status(400).json({ error: 'Filing details required.' });

    // 1. RATE LIMITING - Check user's question rate
    if (!checkRateLimit(userId)) {
      await logQAQuestion(userId, ticker, question, true, 'rate-limit-exceeded');
      return res.status(429).json({ error: 'Too many questions. Please wait before asking another.' });
    }

    // 2. PROMPT INJECTION DETECTION
    if (detectPromptInjection(question)) {
      await logQAQuestion(userId, ticker, question, true, 'prompt-injection-detected');
      return res.status(400).json({ error: 'Invalid question format. Please ask about the filing directly.' });
    }

    // 3. TOPIC VALIDATION - Ensure question is about this filing
    const cachedAnalysis = await getCachedAnalysis(ticker, accessionNumber);
    const companyName = cachedAnalysis?.companyName || '';

    if (!isQuestionOnTopic(question, ticker, companyName, formType)) {
      await logQAQuestion(userId, ticker, question, true, 'off-topic');
      return res.status(400).json({
        error: `Please ask questions related to ${companyName || ticker} and its financial information.`
      });
    }

    // 4. RATE LIMITING FOR PRO FEATURES - Higher limits for pro users
    const user = await getUserById(userId);
    const isProUser = user?.tier === 'pro' || user?.isEffectivelyPro;
    if (!isProUser && question.length > 500) {
      await logQAQuestion(userId, ticker, question, true, 'length-limit-free-user');
      return res.status(400).json({ error: 'Questions limited to 500 characters for free users.' });
    }

    // For 10-K/10-Q/20-F, try to use cached XBRL data first (much smaller, more accurate)
    let contextText = '';
    const cached = await getCachedXBRLData(ticker, accessionNumber);

    if (cached && (formType === '10-K' || formType === '10-Q' || formType === '20-F')) {
      console.log(`[Q&A] Using cached XBRL data for ${ticker}`);
      contextText = cached.qaText;
    } else {
      // Fall back to full filing text for other form types or if no cache
      console.log(`[Q&A] Fetching full filing text for ${ticker}`);
      const { text: filingText } = await fetchFilingText(cik, accessionNumber, primaryDocument, formType);
      if (!filingText) return res.status(400).json({ error: 'Could not fetch filing text.' });

      // For financial filings (10-K/10-Q/20-F), use the enriched text with extracted financial statements
      // For other types, use extractRelevantSections to narrow down
      if (formType === '10-K' || formType === '10-Q' || formType === '20-F') {
        // Financial filings already have tables and statements extracted by fetchFilingText
        console.log(`[Q&A] Using enriched filing text for ${ticker} (with extracted financial statements)`);
        contextText = filingText;
      } else {
        // Non-financial filings: extract relevant sections based on question keywords
        contextText = extractRelevantSections(filingText, question);
      }
    }

    if (!contextText) return res.status(400).json({ error: 'Could not extract filing context.' });

    // Ask Claude about the filing with better context
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      system: `You are a friendly financial analyst explaining a company's report to a high school student. Sound natural and conversational, like you're explaining to a friend over coffee.

Your job: Answer the user's question using ONLY information from the SEC filing provided. Extract the key facts, numbers, and insights, then explain them in plain English that a high school student would understand.

Rules:
- BASE YOUR ANSWER on the actual filing text. Use real numbers, dates, and facts from the document.
- Explain in your own words. DON'T copy or quote official report language word-for-word.
- Use casual, natural language. Talk like a real person explaining to a friend, not a textbook.
- Break down what numbers MEAN for the company, not just what they are. Why do they matter?
- Use specific numbers and dates, but explain them in context. Example: "Revenue grew 15% to $10B because..." not just "Revenue is $10B."
- Keep it short. Use 2-3 short paragraphs, separated by line breaks.
- Be honest. If the filing doesn't clearly address the question, say so. Don't make up answers.
- Share your thinking. Use phrases like "So basically...", "What this means is...", "The interesting part is..."
- For metrics: always provide the actual number from the filing, then explain what it means.`,
      messages: [
        {
          role: 'user',
          content: `Here's the relevant part of the ${formType} filing for ${ticker}:\n\n${contextText}\n\nUser's question: ${question}\n\nAnswer this question using only information from the filing above. Be specific with numbers and dates from the actual document.`
        }
      ]
    });

    const answer = message.content[0]?.text || 'No answer generated.';
    res.json({ question, answer, ticker, formType });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Pre-extract and cache XBRL data for faster Q&A (triggered when filing loads)
app.post('/api/qa/extract-xbrl', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, accessionNumber, cik } = req.body;
    if (!ticker || !formType || !accessionNumber || !cik) {
      return res.status(400).json({ error: 'Missing required fields: ticker, formType, accessionNumber, cik' });
    }

    // Skip extraction for form types that don't have structured XBRL financial data
    if (!['10-K', '10-Q', '20-F'].includes(formType)) {
      return res.json({ status: 'skipped', reason: `Form type ${formType} not supported for XBRL extraction` });
    }

    // Extract and cache
    const result = await preExtractXBRLData(cik, accessionNumber, ticker, formType);

    if (!result) {
      // No XBRL data available is not an error - just return empty result
      return res.json({
        status: 'skipped',
        reason: 'No structured XBRL financial data found for this filing',
        ticker,
        formType,
        accessionNumber,
        dataPoints: 0
      });
    }

    res.json({
      status: 'success',
      ticker,
      formType,
      accessionNumber,
      dataPoints: Object.keys(result.metrics).filter(k => result.metrics[k] !== null).length
    });
  } catch (err) {
    console.error('[extract-xbrl] Error:', err.message);
    // Don't return 500 - just return skipped status to not block analysis display
    res.json({
      status: 'error',
      reason: err.message,
      dataPoints: 0
    });
  }
});

// Helper to escape HTML in email content
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Email Q&A conversation
app.post('/api/qa/email', authMiddleware, async (req, res) => {
  try {
    const { email, ticker, formType, accessionNumber, messages } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email address required' });
    }

    if (!ticker || !formType || !messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (messages.length === 0) {
      return res.status(400).json({ error: 'No messages to send' });
    }

    // Format messages as HTML email
    let emailContent = `<h2>${ticker} ${formType} - Q&A Conversation</h2>`;
    if (accessionNumber) {
      emailContent += `<p style="color: #666; font-size: 0.9em;">Filing: ${accessionNumber}</p>`;
    }
    emailContent += `<hr style="margin: 20px 0;">`;

    messages.forEach(msg => {
      const isUser = msg.role === 'user';
      const bgColor = isUser ? '#e8f5e9' : '#f5f5f5';
      const label = isUser ? 'You' : 'FinRead AI';
      emailContent += `
        <div style="margin-bottom: 20px; padding: 15px; background-color: ${bgColor}; border-radius: 8px;">
          <strong style="color: ${isUser ? '#2e7d32' : '#424242'};">${label}:</strong>
          <p style="margin: 8px 0 0 0; color: #333; line-height: 1.6;">${escapeHtml(msg.text)}</p>
        </div>
      `;
    });

    emailContent += `<hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">`;
    emailContent += `<p style="font-size: 0.85em; color: #999;">Saved from FinRead on ${new Date().toLocaleString()}</p>`;

    // For now, just log to console. In production, use SendGrid, Resend, or nodemailer
    console.log(`[EMAIL] To: ${email}`);
    console.log(`[EMAIL] Subject: FinRead Q&A - ${ticker} ${formType}`);
    console.log(`[EMAIL] Content:`, emailContent);

    // TODO: Integrate with email service (SendGrid, Resend, etc.)
    // For development, we just simulate success
    res.json({
      success: true,
      message: `Email would be sent to ${email}. (Email service not yet configured in dev mode.)`
    });
  } catch (err) {
    console.error('[/api/qa/email] Error:', err);
    res.status(500).json({ error: 'Failed to prepare email' });
  }
});

// ── SHARING ────────────────────────────────────────────────────────────────────

app.post('/api/shares', authMiddleware, async (req, res) => {
  try {
    const { reportId } = req.body;
    if (!reportId) return res.status(400).json({ error: 'Report ID required.' });

    const reports = await readJSON(REPORTS_FILE);
    const report = reports.find(r => r.id === reportId && r.userId === req.user.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    const shares = await readJSON(SHARES_FILE);
    const token = crypto.randomBytes(16).toString('hex');
    const share = {
      token,
      reportId,
      userId: req.user.id,
      userEmail: req.user.email,
      createdAt: new Date().toISOString(),
    };
    shares.push(share);
    await writeJSON(SHARES_FILE, shares);

    res.json({ token, url: `${process.env.PUBLIC_URL || 'http://localhost:3000'}/share/${token}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/shares/:token', async (req, res) => {
  try {
    const shares = await readJSON(SHARES_FILE);
    const share = shares.find(s => s.token === req.params.token);
    if (!share) return res.status(404).json({ error: 'Share not found' });

    const reports = await readJSON(REPORTS_FILE);
    const report = reports.find(r => r.id === share.reportId);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── BATCH PROCESSING & BULK DOWNLOADS ────────────────────────────────────────
app.post('/api/batch', authMiddleware, async (req, res) => {
  try {
    // Check if user is Pro tier
    const users = await readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user || !user.tier || !['pro', 'enterprise'].includes(user.tier)) {
      return res.status(403).json({ error: 'Batch processing requires Pro tier' });
    }

    const { filings, exportFormat } = req.body;
    if (!filings || !Array.isArray(filings) || filings.length === 0) {
      return res.status(400).json({ error: 'At least one filing is required' });
    }
    if (!['csv', 'pdf'].includes(exportFormat)) {
      return res.status(400).json({ error: 'Invalid export format' });
    }

    const batchId = crypto.randomUUID();
    const batch = {
      id: batchId,
      userId: req.user.id,
      filings: filings.map(f => ({ ticker: f.ticker, formType: f.formType, cik: f.cik, accessionNumber: f.accessionNumber })),
      exportFormat,
      status: 'queued', // queued, processing, completed, failed
      progress: 0,
      results: [],
      error: null,
      createdAt: new Date().toISOString(),
      completedAt: null,
    };

    let batches = await readJSON(BATCHES_FILE);
    batches.push(batch);
    await writeJSON(BATCHES_FILE, batches);

    // Start background processing
    processBatchJob(batchId, req.user.id).catch(err => console.error(`[batch] Error processing batch ${batchId}:`, err));

    res.json({ id: batchId, status: 'queued' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/batch/:id', authMiddleware, async (req, res) => {
  try {
    const batches = await readJSON(BATCHES_FILE);
    const batch = batches.find(b => b.id === req.params.id && b.userId === req.user.id);
    if (!batch) return res.status(404).json({ error: 'Batch not found' });

    res.json(batch);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/batch/:id/download', authMiddleware, async (req, res) => {
  try {
    const batches = await readJSON(BATCHES_FILE);
    const batch = batches.find(b => b.id === req.params.id && b.userId === req.user.id);
    if (!batch) return res.status(404).json({ error: 'Batch not found' });
    if (batch.status !== 'completed') return res.status(400).json({ error: 'Batch not yet completed' });

    const filename = `batch-${batch.id}-${new Date().toISOString().split('T')[0]}.${batch.exportFormat}`;
    const filePath = path.join(DATA_DIR, `batch-${batch.id}.${batch.exportFormat}`);

    // Check if file exists
    if (!fsSync.existsSync(filePath)) return res.status(404).json({ error: 'Export file not found' });

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', batch.exportFormat === 'csv' ? 'text/csv' : 'application/pdf');
    res.download(filePath);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Background batch processing function
async function processBatchJob(batchId, userId) {
  try {
    let batches = await readJSON(BATCHES_FILE);
    let batch = batches.find(b => b.id === batchId);
    if (!batch) return console.error(`[batch] Batch ${batchId} not found`);

    batch.status = 'processing';
    batch.progress = 0;
    await writeJSON(BATCHES_FILE, batches);

    const results = [];
    const totalFilings = batch.filings.length;

    for (let i = 0; i < batch.filings.length; i++) {
      const filing = batch.filings[i];
      try {
        console.log(`[batch] Processing filing ${i + 1}/${totalFilings}: ${filing.ticker} ${filing.formType}`);

        // Fetch and analyze filing
        const analysis = await runFullAnalysis(filing.cik, filing.accessionNumber, filing.formType);

        // Extract metrics
        const metrics = await extractAllXBRLMetrics(filing.cik, filing.accessionNumber);
        const sectionMetrics = await extractMetricsFromSections(analysis.sections);
        const mergedMetrics = { ...metrics, ...sectionMetrics };

        results.push({
          ticker: filing.ticker,
          formType: filing.formType,
          accessionNumber: filing.accessionNumber,
          metrics: mergedMetrics,
          sections: analysis.sections,
          success: true,
        });
      } catch (err) {
        console.error(`[batch] Error processing ${filing.ticker} ${filing.formType}:`, err.message);
        results.push({
          ticker: filing.ticker,
          formType: filing.formType,
          accessionNumber: filing.accessionNumber,
          success: false,
          error: err.message,
        });
      }

      batch.progress = Math.round(((i + 1) / totalFilings) * 100);
      batches = await readJSON(BATCHES_FILE);
      const batchIndex = batches.findIndex(b => b.id === batchId);
      if (batchIndex >= 0) {
        batches[batchIndex].progress = batch.progress;
        batches[batchIndex].results = results;
        await writeJSON(BATCHES_FILE, batches);
      }
    }

    // Generate export file
    const filePath = path.join(DATA_DIR, `batch-${batchId}.${batch.exportFormat}`);
    if (batch.exportFormat === 'csv') {
      await generateBatchCSV(results, filePath);
    } else if (batch.exportFormat === 'pdf') {
      await generateBatchPDF(results, filePath);
    }

    batch.status = 'completed';
    batch.completedAt = new Date().toISOString();
    batches = await readJSON(BATCHES_FILE);
    const batchIndex = batches.findIndex(b => b.id === batchId);
    if (batchIndex >= 0) {
      batches[batchIndex] = batch;
      await writeJSON(BATCHES_FILE, batches);
    }

    console.log(`[batch] Batch ${batchId} completed successfully`);
  } catch (err) {
    console.error(`[batch] Batch ${batchId} failed:`, err.message);
    let batches = await readJSON(BATCHES_FILE);
    const batchIndex = batches.findIndex(b => b.id === batchId);
    if (batchIndex >= 0) {
      batches[batchIndex].status = 'failed';
      batches[batchIndex].error = err.message;
      batches[batchIndex].completedAt = new Date().toISOString();
      await writeJSON(BATCHES_FILE, batches);
    }
  }
}

// Helper: Generate CSV export from batch results
async function generateBatchCSV(results, filePath) {
  const headers = ['Ticker', 'Form Type', 'Revenue', 'Net Income', 'Operating CF', 'Capex', 'Free CF', 'Current Ratio', 'Debt-to-Equity', 'Health Score'];
  const rows = results.map(r => {
    if (!r.success) return [r.ticker, r.formType, 'ERROR', r.error];
    const m = r.metrics || {};
    return [
      r.ticker,
      r.formType,
      m.revenue || '—',
      m.netIncome || '—',
      m.operatingCashFlow || '—',
      m.capex || '—',
      m.freeCashFlow || '—',
      m.currentRatio ? m.currentRatio.toFixed(2) : '—',
      m.debtToEquity ? m.debtToEquity.toFixed(2) : '—',
      '—',
    ];
  });

  const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
  await fs.writeFile(filePath, csv);
}

// Helper: Generate PDF export from batch results
async function generateBatchPDF(results, filePath) {
  // Basic PDF generation - can be enhanced with a library like pdfkit
  let content = 'BATCH ANALYSIS REPORT\n\n';
  results.forEach((r, i) => {
    content += `${i + 1}. ${r.ticker} ${r.formType}\n`;
    if (r.success) {
      const m = r.metrics || {};
      content += `   Revenue: ${m.revenue || 'N/A'}\n`;
      content += `   Net Income: ${m.netIncome || 'N/A'}\n`;
      content += `   Operating CF: ${m.operatingCashFlow || 'N/A'}\n`;
    } else {
      content += `   ERROR: ${r.error}\n`;
    }
    content += '\n';
  });

  await fs.writeFile(filePath, content);
}

// ── CUSTOM ALERTS & TRIGGERS ──────────────────────────────────────────────────
app.post('/api/alerts', authMiddleware, async (req, res) => {
  try {
    // Check if user is Pro tier
    const users = await readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user || !user.tier || !['pro', 'enterprise'].includes(user.tier)) {
      return res.status(403).json({ error: 'Custom alerts require Pro tier' });
    }

    const { ticker, metric, operator, threshold, notificationMethod, webhookUrl } = req.body;
    if (!ticker || !metric || !operator || threshold === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate operator
    if (!['>', '<', '=', '>=', '<='].includes(operator)) {
      return res.status(400).json({ error: 'Invalid operator' });
    }

    // Validate notification method
    if (!['email', 'slack', 'webhook'].includes(notificationMethod)) {
      return res.status(400).json({ error: 'Invalid notification method' });
    }

    if (notificationMethod === 'webhook' && !webhookUrl) {
      return res.status(400).json({ error: 'Webhook URL required for webhook method' });
    }

    const alert = {
      id: crypto.randomUUID(),
      userId: req.user.id,
      ticker,
      metric, // health_score, revenue, net_income, operating_cf, current_ratio, debt_to_equity
      operator,
      threshold: parseFloat(threshold),
      notificationMethod,
      webhookUrl: webhookUrl || null,
      slackUserId: null, // Will be set during Slack auth
      active: true,
      lastTriggeredAt: null,
      createdAt: new Date().toISOString(),
    };

    let alerts = await readJSON(ALERTS_FILE);
    alerts.push(alert);
    await writeJSON(ALERTS_FILE, alerts);

    res.json(alert);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/alerts', authMiddleware, async (req, res) => {
  try {
    const alerts = await readJSON(ALERTS_FILE);
    const userAlerts = alerts.filter(a => a.userId === req.user.id);
    res.json(userAlerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    const { active, threshold, operator } = req.body;
    let alerts = await readJSON(ALERTS_FILE);
    const alertIndex = alerts.findIndex(a => a.id === req.params.id && a.userId === req.user.id);

    if (alertIndex < 0) return res.status(404).json({ error: 'Alert not found' });

    if (active !== undefined) alerts[alertIndex].active = active;
    if (threshold !== undefined) alerts[alertIndex].threshold = parseFloat(threshold);
    if (operator !== undefined) alerts[alertIndex].operator = operator;

    await writeJSON(ALERTS_FILE, alerts);
    res.json(alerts[alertIndex]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/alerts/:id', authMiddleware, async (req, res) => {
  try {
    let alerts = await readJSON(ALERTS_FILE);
    alerts = alerts.filter(a => !(a.id === req.params.id && a.userId === req.user.id));
    await writeJSON(ALERTS_FILE, alerts);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/alerts/history', authMiddleware, async (req, res) => {
  try {
    const history = await readJSON(ALERT_HISTORY_FILE);
    const userHistory = history.filter(h => h.userId === req.user.id).slice(-50); // Last 50
    res.json(userHistory);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: Check alerts when metrics are extracted
async function checkAndTriggerAlerts(ticker, metrics) {
  try {
    const alerts = await readJSON(ALERTS_FILE);
    const relevantAlerts = alerts.filter(a => a.active && a.ticker.toUpperCase() === ticker.toUpperCase());

    for (const alert of relevantAlerts) {
      const value = metrics[alert.metric];
      if (value === null || value === undefined) continue;

      let triggered = false;
      const numValue = parseFloat(value);

      switch (alert.operator) {
        case '>': triggered = numValue > alert.threshold; break;
        case '<': triggered = numValue < alert.threshold; break;
        case '=': triggered = Math.abs(numValue - alert.threshold) < 0.01; break;
        case '>=': triggered = numValue >= alert.threshold; break;
        case '<=': triggered = numValue <= alert.threshold; break;
      }

      if (triggered) {
        await triggerAlert(alert, ticker, alert.metric, numValue);
      }
    }
  } catch (err) {
    console.error('[alerts] Error checking alerts:', err.message);
  }
}

// Helper: Trigger alert notification
async function triggerAlert(alert, ticker, metric, value) {
  try {
    const history = {
      id: crypto.randomUUID(),
      alertId: alert.id,
      userId: alert.userId,
      ticker,
      metric,
      value,
      operator: alert.operator,
      threshold: alert.threshold,
      triggered: true,
      triggeredAt: new Date().toISOString(),
    };

    // Send notification based on method
    if (alert.notificationMethod === 'email') {
      console.log(`[alert] Email notification: ${ticker} ${metric} = ${value}`);
      // In production, send actual email via nodemailer
    } else if (alert.notificationMethod === 'slack' && alert.slackUserId) {
      console.log(`[alert] Slack notification to ${alert.slackUserId}: ${ticker} ${metric} = ${value}`);
      // In production, send via Slack API
    } else if (alert.notificationMethod === 'webhook' && alert.webhookUrl) {
      try {
        await fetch(alert.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(history),
        });
      } catch (err) {
        console.error(`[alert] Webhook failed for ${alert.id}:`, err.message);
      }
    }

    // Record in history
    let alertHistory = await readJSON(ALERT_HISTORY_FILE);
    alertHistory.push(history);
    await writeJSON(ALERT_HISTORY_FILE, alertHistory);

    // Update last triggered time
    let alerts = await readJSON(ALERTS_FILE);
    const alertIndex = alerts.findIndex(a => a.id === alert.id);
    if (alertIndex >= 0) {
      alerts[alertIndex].lastTriggeredAt = new Date().toISOString();
      await writeJSON(ALERTS_FILE, alerts);
    }
  } catch (err) {
    console.error('[alert] Error triggering alert:', err.message);
  }
}

// ── FINANCIAL METRICS & RATIOS ────────────────────────────────────────────────
// Helper: extract numeric value from text (e.g., "$383.3B" -> 383.3)
function extractNumericValue(text) {
  if (!text) return null;
  // Capture optional negative sign, dollar sign, numbers, and unit suffix (B, M, K)
  const match = text.match(/(-?\$?\(?[\d,]+\.?[\d,]*\)?|\([\d,]+\.?[\d,]*\))\s*([BMK])?/i);
  if (!match) return null;

  let value = match[1].replace(/,/g, '').replace(/\$/g, '');
  const unit = match[2] ? match[2].toUpperCase() : '';

  // Handle parentheses notation for negative numbers: (1234) = -1234
  if (value.startsWith('(') && value.endsWith(')')) {
    value = '-' + value.slice(1, -1);
  }

  let numericValue = parseFloat(value);

  // Normalize to billions: B=1, M=0.001, K=0.000001
  // This ensures all values are on the same scale for ratio calculations
  if (unit === 'B') {
    // Already in billions
  } else if (unit === 'M') {
    numericValue = numericValue / 1000;
  } else if (unit === 'K') {
    numericValue = numericValue / 1000000;
  }

  return numericValue;
}

// Helper: extract numbers from text snippets using patterns
function extractNumbersFromText(text, patterns) {
  if (!text) return null;
  const lowerText = text.toLowerCase();

  for (const pattern of patterns) {
    // Look for the pattern followed by numbers (immediate)
    const regex = new RegExp(`${pattern}[:\\s]+\\$?([\\d,]+(?:\\.\\d+)?)`);
    const match = lowerText.match(regex);
    if (match) {
      return parseFloat(match[1].replace(/,/g, ''));
    }

    // For table formats: find pattern, then look in next 200 chars for substantial number
    // This handles cases like "Net income | 4 | — | — | 3,794"
    const tableRegex = new RegExp(`${pattern}[^\\d]*((?:[\\d,]+\\s+)+[\\d,]+)`);
    const tableMatch = lowerText.match(tableRegex);
    if (tableMatch) {
      // Extract all numbers from the match and take the largest one
      const numbersStr = tableMatch[1];
      const numbers = numbersStr.split(/\s+/).filter(n => n).map(n => parseFloat(n.replace(/,/g, '')));
      if (numbers.length > 0) {
        const largestNum = Math.max(...numbers);
        if (largestNum > 100) { // Avoid noise - financial metrics should be > 100M
          return largestNum;
        }
      }
    }
  }
  return null;
}

// Helper: extract figures from sections with flexible pattern matching and fallback
function extractMetricsFromSections(sections) {
  const metrics = {
    revenue: null,
    netIncome: null,
    grossProfit: null,
    operatingIncome: null,
    operatingCashFlow: null,
    capex: null,
    freeCashFlow: null,
    totalAssets: null,
    currentAssets: null,
    currentLiabilities: null,
    totalLiabilities: null,
    debt: null,
    equity: null,
    liabilities: null
  };

  console.log('[extractMetricsFromSections] ===== EXTRACTING METRICS =====');
  console.log('[extractMetricsFromSections] Section keys:', Object.keys(sections || {}));

  // Log what's in each section
  Object.entries(sections || {}).forEach(([key, section]) => {
    console.log(`[extractMetricsFromSections] Section "${key}":`, {
      hasKeyFigures: !!section?.key_figures,
      keyFiguresCount: section?.key_figures?.length || 0,
      hasQuote: !!section?.key_quote,
      hasExcerpt: !!section?.excerpt,
      hasBullets: !!section?.bullets
    });
    if (section?.key_figures?.length > 0) {
      console.log(`  Key figures:`, section.key_figures.map(f => `"${f.label}": ${f.value}`));
    }
  });

  // Helper to find by multiple patterns in key_figures
  const findByPatterns = (figures, patterns, debugLabel) => {
    if (!figures) {
      console.log(`[extractMetrics] ${debugLabel}: no figures array`);
      return null;
    }

    console.log(`[extractMetrics] ${debugLabel}: checking ${figures.length} figures`);
    figures.forEach((f, i) => {
      console.log(`  [${i}] "${f.label}": ${f.value}`);
    });

    for (const pattern of patterns) {
      // Find ALL figures matching this pattern, not just the first
      const matches = figures.filter(f => {
        const label = f.label?.toLowerCase() || '';
        return pattern.test(label);
      });

      // Return the first match with a valid numeric value
      for (const fig of matches) {
        const value = extractNumericValue(fig.value);
        if (value !== null && !isNaN(value)) {
          console.log(`[extractMetrics] ${debugLabel}: MATCHED pattern ${pattern} -> "${fig.label}": ${value}`);
          return value;
        }
      }
    }
    console.log(`[extractMetrics] ${debugLabel}: NO MATCH for patterns`);
    return null;
  };

  // Collect all figures from all sections and all text content
  const allFigures = [];
  let allText = '';
  const figuresBySection = {};

  Object.entries(sections || {}).forEach(([sectionKey, section]) => {
    if (section?.key_figures && Array.isArray(section.key_figures)) {
      console.log(`[extractMetrics] Section "${sectionKey}": ${section.key_figures.length} figures`);
      figuresBySection[sectionKey] = section.key_figures;
      allFigures.push(...section.key_figures);
    }
    // Also collect text content for fallback extraction
    if (section?.key_quote) allText += ' ' + section.key_quote;
    if (section?.context) allText += ' ' + section.context;
    if (section?.excerpt) allText += ' ' + section.excerpt; // Include excerpt if available
    if (section?.bullets && Array.isArray(section.bullets)) {
      allText += ' ' + section.bullets.join(' ');
    }
    // Also add key_figures values as text for searching
    if (section?.key_figures && Array.isArray(section.key_figures)) {
      allText += ' ' + section.key_figures.map(f => `${f.label} ${f.value}`).join(' ');
    }
  });

  // Extract metrics with multiple pattern alternatives + fallback from text
  // Extract from specific sections first, then fallback to all figures
  const revenueFigures = figuresBySection['revenue'] || [];
  const incomeFigures = figuresBySection['income'] || [];

  metrics.revenue = findByPatterns(revenueFigures.length ? revenueFigures : allFigures, [
    /^(total\s+)?revenues?$/i,
    /net\s+revenues?/i,
    /sales/i,
    /^revenue$/i
  ], 'revenue') || extractNumbersFromText(allText, ['revenue', 'revenues', 'sales', 'total sales']);

  // Try primary patterns first
  metrics.netIncome = findByPatterns(incomeFigures.length ? incomeFigures : allFigures, [
    /^net\s+(income|earnings|loss|profit)$/i,
    /^net\s+income\s+\(/i,
    /^net\s+loss$/i,
    /^net\s+profit$/i,
    /^net\s+earnings$/i,
    /^consolidated\s+net\s+(income|earnings)$/i,
    /^income\s+before\s+tax/i,
    /^net\s+(income|earnings|loss|profit)/i,
    /^earnings$/i,
    /^earnings\s+\(/i,
    /^net\s+earnings\s+per/i,
    /^profit$/i
  ], 'netIncome');

  // If not found in key figures, try text search (more thorough)
  if (!metrics.netIncome) {
    metrics.netIncome = extractNumbersFromText(allText, [
      'net income attributable to common stockholders',
      'net income attributable to stockholders',
      'net income attributable to tesla',
      'net income',
      'net earnings',
      'consolidated net income',
      'net profit'
    ]);
  }

  // Try income before taxes as fallback (can estimate net income from this)
  if (!metrics.netIncome) {
    const incomeBT = extractNumbersFromText(allText, [
      'income before income tax',
      'income before income taxes',
      'income before provision for income tax',
      'earnings before income tax'
    ]);
    if (incomeBT) {
      // Estimate net income as ~75-85% of income before tax (assuming ~15-25% tax rate)
      metrics.netIncome = incomeBT * 0.80;
      console.log(`[extractMetrics] Estimated netIncome from income before tax: ${metrics.netIncome} (IBT was ${incomeBT})`);
    }
  }

  // Final fallback patterns
  if (!metrics.netIncome) {
    metrics.netIncome = findByPatterns(allFigures, [/^net\s+(income|earnings|loss|profit)|^earnings$|^profit$/i], 'netIncome')
      || findByPatterns(allFigures, [/net.*(income|earnings)|bottom\s+line/i], 'netIncome');
  }

  metrics.operatingIncome = findByPatterns(incomeFigures.length ? incomeFigures : allFigures, [
    /^operating\s+(income|earnings|loss)/i,
    /operating\s+income\s+\(/i,
    /loss\s+from\s+operations/i,
    /income\s+from\s+operations/i,
    /operating\s+profit\s+loss/i,
    /income\s+from\s+operations/i
  ], 'operatingIncome')
  || extractNumbersFromText(allText, ['operating income', 'operating loss', 'operating earnings', 'operating profit', 'income from operations'])
  || findByPatterns(allFigures, [/operating.*income/i], 'operatingIncome');

  metrics.grossProfit = findByPatterns(incomeFigures.length ? incomeFigures : allFigures, [
    /^gross\s+(profit|loss|margin)/i,
    /gross\s+profit\s+\(/i,
    /gross\s+loss/i,
    /gross\s+margin/i,
    /cost\s+of\s+revenues?\s*$/i
  ], 'grossProfit')
  || extractNumbersFromText(allText, ['gross profit', 'gross loss', 'gross margin', 'cost of revenue'])
  || findByPatterns(allFigures, [/gross.*profit/i], 'grossProfit');

  // Try to extract balance sheet metrics first from the "balance" section specifically
  const balanceFigures = figuresBySection['balance'] || [];

  metrics.totalAssets = findByPatterns(balanceFigures.length ? balanceFigures : allFigures, [
    /total\s+assets/i,
    /^assets$/i
  ], 'totalAssets') || extractNumbersFromText(allText, ['total assets', 'assets']);

  metrics.currentAssets = findByPatterns(balanceFigures.length ? balanceFigures : allFigures, [
    /^current\s+assets$/i,
    /^current\s+assets\s+\(/i,
    /cash\s+and.*assets/i,
    /cash.*equivalents/i,
    /current\s+assets/i
  ], 'currentAssets') || extractNumbersFromText(allText, ['current assets', 'cash and equivalents']);

  metrics.currentLiabilities = findByPatterns(balanceFigures.length ? balanceFigures : allFigures, [
    /^current\s+liabilities?$/i,
    /^current\s+liabilities?\s+\(/i,
    /^current\s+obligations/i,
    /liabilities\s+current/i,
    /short.?term\s+liabilities?/i,
    /current\s+liabilities?/i
  ], 'currentLiabilities')
  || extractNumbersFromText(allText, ['current liabilities', 'current obligations', 'current liabilities and deferred'])
  || findByPatterns(allFigures, [/current.*liabilities/i], 'currentLiabilities');

  metrics.liabilities = findByPatterns(balanceFigures.length ? balanceFigures : allFigures, [
    /total\s+liabilities?/i,
    /^liabilities?$/i,
    /liabilities\s+and.*equity/i,
    /^liabilities/i
  ], 'liabilities') || extractNumbersFromText(allText, ['total liabilities', 'liabilities']);

  // Alias for API compatibility
  metrics.totalLiabilities = metrics.liabilities;

  metrics.equity = findByPatterns(balanceFigures.length ? balanceFigures : allFigures, [
    /stockholders?'?\s+equity/i,
    /shareholders?'?\s+equity/i,
    /total\s+equity/i,
    /total\s+stockholders/i,
    /members?'?\s+equity/i
  ], 'equity') || extractNumbersFromText(allText, ['stockholders equity', 'shareholders equity', 'total equity']);

  metrics.debt = findByPatterns(allFigures, [
    /^total\s+debt$/i,
    /^total\s+debt\s+\(/i,
    /long.?term\s+debt/i,
    /short.?term\s+debt/i,
    /total\s+borrowings/i,
    /total\s+debt/i
  ], 'debt') || extractNumbersFromText(allText, ['total debt', 'long-term debt', 'borrowings']);

  // Extract cash flow metrics with multi-layered fallbacks
  const cashFlowFigures = figuresBySection['cashflow'] || figuresBySection['cash flow'] || [];

  // Operating Cash Flow - multi-layered extraction
  metrics.operatingCashFlow = findByPatterns(cashFlowFigures.length ? cashFlowFigures : allFigures, [
    /^operating\s+cash\s+flow$/i,
    /^net\s+cash.*operating/i,
    /cash\s+(?:generated\s+)?(?:provided\s+)?by\s+operating\s+activities/i,
    /cash\s+flow\s+(?:from|generated\s+by)\s+operations/i,
    /(?:net\s+)?cash\s+(?:provided\s+by|used\s+in)\s+operating\s+activities/i,
    /^operating\s+activities$/i,
    /cash\s+(?:provided\s+by|from)\s+operating/i,
    /operating\s+cash\s+flows?/i,
    /operating\s+activities\s+subtotal/i
  ], 'operatingCashFlow')
  || extractNumbersFromText(allText, ['operating cash flow', 'cash flow from operations', 'cash generated by operating', 'net cash from operating', 'cash from operating activities', 'operating activities', 'net cash provided by operating', 'cash flows from operating activities'])
  || findByPatterns(allFigures, [/operating.*cash|cash.*operating|^operating|^net\s+cash.*operations/i], 'operatingCashFlow');

  // Capital Expenditures - multi-layered extraction with very aggressive fallbacks
  metrics.capex = findByPatterns(cashFlowFigures.length ? cashFlowFigures : allFigures, [
    /^(capital\s+)?expenditures?$/i,
    /^capex$/i,
    /purchases?\s+of\s+property,?\s+plant.*equipment/i,
    /purchases?\s+of\s+(?:property\s+and\s+)?equipment/i,
    /capital\s+expenditures?/i,
    /payments?\s+(?:to\s+)?acquire.*property/i,
    /property,?\s+plant.*equipment/i,
    /acquisitions?\s+of\s+(?:property|ppe|equipment)/i,
    /purchase.*(?:equipment|ppe|property)/i,
    /capital\s+(?:outlay|spending)/i,
    /ppe\s+purchase/i,
    /property\s+acquisition/i,
    /purchase.*capital/i,
    /investing\s+activities\s+subtotal/i
  ], 'capex')
  || extractNumbersFromText(allText, ['capital expenditures', 'capex', 'purchases of property plant and equipment', 'purchases of property', 'property plant equipment', 'purchases of equipment', 'acquisition of property', 'purchases of ppe', 'property and equipment purchases', 'payments to acquire property', 'capital assets', 'capital outlay', 'investing activities'])
  || findByPatterns(allFigures, [/^purchases?|^capital|^capex|purchase.*property|equipment.*purchases?/i], 'capex');

  // Stock Buybacks - extract with very aggressive multi-layered fallback
  const buybackPatterns = [
    /^stock\s+buybacks?$/i,
    /^share\s+repurchases?$/i,
    /^repurchases?\s+of\s+(?:common\s+)?stock$/i,
    /^repurchases?\s+of\s+common\s+stock/i,
    /repurchases?\s+of\s+(?:common\s+)?stock/i,
    /payments?\s+(?:for\s+)?repurchase/i,
    /treasury\s+stock\s+(?:purchases?|repurchases?)/i,
    /share\s+repurchase/i,
    /share\s+buyback/i,
    /^buybacks?$/i,
    /^repurchases?$/i,
    /stock\s+repurchase/i,
    /buyback/i,
    /financing\s+activities\s+subtotal/i
  ];

  const buybacksValue = findByPatterns(cashFlowFigures.length ? cashFlowFigures : allFigures, buybackPatterns, 'buybacks')
  || extractNumbersFromText(allText, ['stock repurchase', 'repurchases of common stock', 'share buyback', 'repurchase of stock', 'treasury stock purchase', 'repurchase activity', 'repurchased shares', 'share repurchase', 'stock buyback', 'treasury stock repurchase', 'share repurchases', 'buyback'])
  || findByPatterns(allFigures, [/^repurchase|^buyback|treasury.*stock|common\s+stock.*repurchase|share.*repurchase|stock.*repurchase/i], 'buybacks');

  if (buybacksValue) {
    metrics.stockBuybacks = buybacksValue;
  }

  // Free Cash Flow - always calculate if we have the inputs
  if (metrics.operatingCashFlow && metrics.capex) {
    metrics.freeCashFlow = metrics.operatingCashFlow - (metrics.capex > 0 ? metrics.capex : Math.abs(metrics.capex));
  } else if (metrics.operatingCashFlow) {
    // If we have OCF but not capex, still show OCF as approximation
    metrics.freeCashFlow = metrics.operatingCashFlow;
  }

  // Ensure all metrics have at least a value (for consistent display)
  // Missing metrics are marked as null, but at least we tried to extract them
  if (!metrics.grossProfit && metrics.revenue && metrics.operatingIncome) {
    // Estimate gross profit if operating income is known
    metrics.grossProfit = metrics.operatingIncome * 1.5; // Rough estimate
  }

  return metrics;
}

// Helper: Calculate enhanced financial health score using all 13 metrics
// Scoring components: Profitability (25%), Cash Flow Quality (25%), Leverage (20%), Growth (20%), Efficiency (10%)
function calculateHealthScore(metrics, ratios, cashRunway, growthTrends) {
  let scores = {
    profitability: 50,
    cashFlowQuality: 50,
    leverage: 50,
    growth: 50,
    efficiency: 50
  };

  console.log(`[healthScore] Starting calculation with metrics:`, {
    revenue: metrics.revenue,
    grossProfit: metrics.grossProfit,
    operatingIncome: metrics.operatingIncome,
    netIncome: metrics.netIncome,
    operatingCashFlow: metrics.operatingCashFlow,
    freeCashFlow: metrics.freeCashFlow
  });

  // PROFITABILITY (0-100): Multi-level analysis using gross, operating, and net profit
  // Use multiple profit signals for robust assessment
  let profitabilitySignals = [];

  // Signal 1: Gross Profit Margin (indicates pricing power and cost control)
  if (metrics.revenue && metrics.grossProfit) {
    const grossMargin = (metrics.grossProfit / metrics.revenue) * 100;
    // Excellent: >50%, Good: 30-50%, Fair: 15-30%, Poor: <15%
    if (grossMargin > 50) profitabilitySignals.push(90);
    else if (grossMargin > 30) profitabilitySignals.push(75);
    else if (grossMargin > 15) profitabilitySignals.push(50);
    else profitabilitySignals.push(25);
    console.log(`[healthScore] Gross margin: ${grossMargin.toFixed(1)}%`);
  }

  // Signal 2: Operating Profit Margin (indicates operational efficiency)
  if (metrics.revenue && metrics.operatingIncome) {
    const operatingMargin = (metrics.operatingIncome / metrics.revenue) * 100;
    // Excellent: >20%, Good: 10-20%, Fair: 0-10%, Poor: <0%
    if (operatingMargin > 20) profitabilitySignals.push(90);
    else if (operatingMargin > 10) profitabilitySignals.push(75);
    else if (operatingMargin > 0) profitabilitySignals.push(50);
    else profitabilitySignals.push(20);
    console.log(`[healthScore] Operating margin: ${operatingMargin.toFixed(1)}%`);
  }

  // Signal 3: Net Profit Margin (bottom line profitability)
  if (metrics.revenue && metrics.netIncome) {
    if (metrics.netIncome < 0) {
      // Company is losing money
      profitabilitySignals.push(15);
      console.log(`[healthScore] Net income: NEGATIVE (loss)`);
    } else {
      const netMargin = (metrics.netIncome / metrics.revenue) * 100;
      // Excellent: >15%, Good: 7-15%, Fair: 3-7%, Weak: 0-3%
      if (netMargin > 15) profitabilitySignals.push(90);
      else if (netMargin > 7) profitabilitySignals.push(75);
      else if (netMargin > 3) profitabilitySignals.push(55);
      else profitabilitySignals.push(35);
      console.log(`[healthScore] Net margin: ${netMargin.toFixed(1)}%`);
    }
  }

  // Signal 4: ROE (Return on Equity) - shareholder value creation
  if (ratios.roe !== undefined) {
    const roe = parseFloat(ratios.roe) || 0;
    if (roe < 0) profitabilitySignals.push(10);
    else if (roe > 20) profitabilitySignals.push(90);
    else if (roe > 15) profitabilitySignals.push(80);
    else if (roe > 10) profitabilitySignals.push(70);
    else if (roe > 5) profitabilitySignals.push(50);
    else profitabilitySignals.push(30);
    console.log(`[healthScore] ROE: ${roe.toFixed(1)}%`);
  }

  // Average all profitability signals for robust score
  if (profitabilitySignals.length > 0) {
    scores.profitability = Math.round(
      profitabilitySignals.reduce((a, b) => a + b) / profitabilitySignals.length
    );
  }

  // PHASE 2: Apply growth trends as profitability modifier
  if (growthTrends && growthTrends.hasData) {
    const revenueGrowth = parseFloat(growthTrends.revenueGrowth);
    const marginChange = parseFloat(growthTrends.netMarginChange);

    // Strong revenue growth = bonus (+10 points per 20% growth, capped at +15)
    if (revenueGrowth > 0) {
      const growthBonus = Math.min(15, Math.round(revenueGrowth / 20 * 10));
      scores.profitability = Math.min(100, scores.profitability + growthBonus);
    } else if (revenueGrowth < -10) {
      // Revenue declining significantly = penalty (-15 points)
      scores.profitability = Math.max(20, scores.profitability - 15);
    }

    // Improving margins = bonus (+5 points per 2 percentage point improvement)
    if (marginChange > 0) {
      const marginBonus = Math.min(10, Math.round(marginChange / 2 * 5));
      scores.profitability = Math.min(100, scores.profitability + marginBonus);
    } else if (marginChange < -3) {
      // Margin compression = penalty (-10 points)
      scores.profitability = Math.max(20, scores.profitability - 10);
    }
  }

  // CASH FLOW QUALITY (0-100): Multi-factor analysis of cash generation and quality
  // Better indicator than just current ratio - measures cash velocity and burn rate
  let cashFlowSignals = [];

  // Signal 1: Operating Cash Flow (core cash generation from operations)
  if (metrics.operatingCashFlow !== null && metrics.operatingCashFlow !== undefined) {
    if (metrics.operatingCashFlow < 0) {
      // Burning cash - critical issue
      cashFlowSignals.push(10);
      console.log(`[healthScore] Operating CF: NEGATIVE (burning cash)`);
    } else if (metrics.revenue && metrics.operatingCashFlow > 0) {
      const ocfMargin = (metrics.operatingCashFlow / metrics.revenue) * 100;
      // Strong: >20%, Good: 10-20%, Fair: 5-10%, Weak: <5%
      if (ocfMargin > 20) cashFlowSignals.push(95);
      else if (ocfMargin > 10) cashFlowSignals.push(85);
      else if (ocfMargin > 5) cashFlowSignals.push(70);
      else cashFlowSignals.push(50);
      console.log(`[healthScore] Operating CF margin: ${ocfMargin.toFixed(1)}%`);
    }
  }

  // Signal 2: Free Cash Flow (OCF - CapEx = cash available for debt/dividends/growth)
  if (metrics.freeCashFlow !== null && metrics.freeCashFlow !== undefined) {
    if (metrics.freeCashFlow < 0) {
      // Negative FCF - company investing heavily or burning cash
      cashFlowSignals.push(25);
      console.log(`[healthScore] Free CF: NEGATIVE`);
    } else if (metrics.revenue && metrics.freeCashFlow > 0) {
      const fcfMargin = (metrics.freeCashFlow / metrics.revenue) * 100;
      // Strong: >15%, Good: 8-15%, Fair: 3-8%, Weak: <3%
      if (fcfMargin > 15) cashFlowSignals.push(95);
      else if (fcfMargin > 8) cashFlowSignals.push(80);
      else if (fcfMargin > 3) cashFlowSignals.push(65);
      else cashFlowSignals.push(45);
      console.log(`[healthScore] Free CF margin: ${fcfMargin.toFixed(1)}%`);
    }
  }

  // Signal 3: Cash Conversion (Net Income to Operating CF ratio - quality of earnings)
  if (metrics.netIncome && metrics.operatingCashFlow && metrics.netIncome > 0) {
    const cashConversion = (metrics.operatingCashFlow / metrics.netIncome);
    // >1.0 = excellent (all earnings converted to cash), 0.7-1.0 = good, <0.7 = concerning
    if (cashConversion > 1.2) cashFlowSignals.push(95);
    else if (cashConversion > 1.0) cashFlowSignals.push(85);
    else if (cashConversion > 0.7) cashFlowSignals.push(70);
    else cashFlowSignals.push(40);
    console.log(`[healthScore] Cash conversion ratio: ${cashConversion.toFixed(2)}`);
  }

  // Signal 4: Current Ratio (short-term liquidity from balance sheet)
  if (ratios.currentRatio !== undefined) {
    const cr = parseFloat(ratios.currentRatio) || 0;
    if (cr >= 1.5 && cr <= 2.5) cashFlowSignals.push(90);
    else if (cr >= 1.0 && cr < 1.5) cashFlowSignals.push(75);
    else if (cr >= 0.8 && cr < 1.0) cashFlowSignals.push(50);
    else if (cr < 0.8) cashFlowSignals.push(20);
    else cashFlowSignals.push(95);
    console.log(`[healthScore] Current ratio: ${cr.toFixed(2)}`);
  }

  // Average all cash flow signals
  if (cashFlowSignals.length > 0) {
    scores.cashFlowQuality = Math.round(
      cashFlowSignals.reduce((a, b) => a + b) / cashFlowSignals.length
    );
  }

  // LEVERAGE (0-100): Multi-factor debt assessment
  let leverageSignals = [];

  if (ratios.debtToEquity !== undefined) {
    const dte = parseFloat(ratios.debtToEquity) || 0;
    // Lower is better: 0-0.5 excellent, 0.5-1.0 good, 1.0-2.0 moderate, >2.0 risky
    if (dte <= 0.5) leverageSignals.push(95);
    else if (dte <= 1.0) leverageSignals.push(80);
    else if (dte <= 2.0) leverageSignals.push(60);
    else leverageSignals.push(Math.max(15, 60 - (dte - 2) * 10));
    console.log(`[healthScore] Debt-to-equity: ${dte.toFixed(2)}`);
  }

  // Can service debt? - Operating Income / Interest coverage
  if (metrics.operatingIncome && ratios.interestCoverage !== undefined) {
    const ic = parseFloat(ratios.interestCoverage) || 0;
    // >5x excellent, 3-5x good, 2-3x fair, <2x risky
    if (ic > 5) leverageSignals.push(90);
    else if (ic > 3) leverageSignals.push(75);
    else if (ic > 2) leverageSignals.push(55);
    else leverageSignals.push(25);
    console.log(`[healthScore] Interest coverage: ${ic.toFixed(2)}x`);
  }

  // Log additional return metrics for transparency
  if (ratios.roa !== undefined) {
    console.log(`[healthScore] Return on Assets (ROA): ${ratios.roa}%`);
  }
  if (ratios.roic !== undefined) {
    console.log(`[healthScore] Return on Invested Capital (ROIC): ${ratios.roic}%`);
  }
  if (ratios.effectiveTaxRate !== undefined) {
    console.log(`[healthScore] Effective Tax Rate: ${ratios.effectiveTaxRate}%`);
  }

  // Log earnings quality and working capital metrics
  if (ratios.accrualsRatio !== undefined) {
    console.log(`[healthScore] Accruals Ratio: ${ratios.accrualsRatio}% (earnings quality)`);
  }
  if (ratios.workingCapital !== undefined) {
    console.log(`[healthScore] Working Capital: $${ratios.workingCapital}B`);
  }
  if (ratios.workingCapitalPercent !== undefined) {
    console.log(`[healthScore] Working Capital as % of Revenue: ${ratios.workingCapitalPercent}%`);
  }

  // Log operational efficiency metrics
  if (ratios.operatingExpenseRatio !== undefined) {
    console.log(`[healthScore] Operating Expense Ratio: ${ratios.operatingExpenseRatio}%`);
  }
  if (ratios.fcfConversionRate !== undefined) {
    console.log(`[healthScore] FCF Conversion Rate: ${ratios.fcfConversionRate}x (profit to free cash)`);
  }
  if (ratios.fcfYield !== undefined) {
    console.log(`[healthScore] FCF Yield: ${ratios.fcfYield}%`);
  }
  if (ratios.capexIntensity !== undefined) {
    console.log(`[healthScore] CapEx Intensity: ${ratios.capexIntensity}% of revenue`);
  }
  if (ratios.netDebtToFCF !== undefined) {
    console.log(`[healthScore] Net Debt / FCF: ${ratios.netDebtToFCF} years to payoff`);
  }
  if (ratios.returnOnCapex !== undefined) {
    console.log(`[healthScore] Return on CapEx: ${ratios.returnOnCapex}x`);
  }

  if (leverageSignals.length > 0) {
    scores.leverage = Math.round(
      leverageSignals.reduce((a, b) => a + b) / leverageSignals.length
    );
  }

  // GROWTH (0-100): Revenue and profitability expansion trends
  let growthSignals = [];

  if (growthTrends && growthTrends.hasData) {
    const revenueGrowth = parseFloat(growthTrends.revenueGrowth) || 0;
    const marginChange = parseFloat(growthTrends.netMarginChange) || 0;

    // Revenue growth signal
    if (revenueGrowth > 30) growthSignals.push(95);
    else if (revenueGrowth > 15) growthSignals.push(85);
    else if (revenueGrowth > 5) growthSignals.push(70);
    else if (revenueGrowth > 0) growthSignals.push(55);
    else if (revenueGrowth > -10) growthSignals.push(40);
    else growthSignals.push(20);
    console.log(`[healthScore] Revenue growth: ${revenueGrowth.toFixed(1)}%`);

    // Margin expansion signal
    if (marginChange > 5) growthSignals.push(90);
    else if (marginChange > 2) growthSignals.push(80);
    else if (marginChange > 0) growthSignals.push(65);
    else if (marginChange > -3) growthSignals.push(50);
    else growthSignals.push(30);
    console.log(`[healthScore] Margin change: ${marginChange.toFixed(1)}pp`);

    // Company growing efficiently? (both revenue and margin improving)
    if (revenueGrowth > 10 && marginChange > 0) {
      growthSignals.push(90);
    }
  } else {
    // No growth data available - neutral
    growthSignals.push(50);
  }

  if (growthSignals.length > 0) {
    scores.growth = Math.round(
      growthSignals.reduce((a, b) => a + b) / growthSignals.length
    );
  }

  // EFFICIENCY (0-100): Asset utilization and cash velocity
  let efficiencySignals = [];

  if (ratios.assetTurnover !== undefined) {
    const at = parseFloat(ratios.assetTurnover) || 0;
    // Ideal: 1-2x, Good: 0.7-1x, Weak: <0.7x
    if (at > 2) efficiencySignals.push(90);
    else if (at > 1.5) efficiencySignals.push(85);
    else if (at > 1) efficiencySignals.push(75);
    else if (at > 0.7) efficiencySignals.push(65);
    else efficiencySignals.push(40);
    console.log(`[healthScore] Asset turnover: ${at.toFixed(2)}x`);
  }

  // Cash to debt paydown capacity (OCF / Total Debt)
  if (metrics.operatingCashFlow && metrics.totalLiabilities && metrics.totalLiabilities > 0) {
    const debtPaydownCapacity = metrics.operatingCashFlow / metrics.totalLiabilities;
    // Can pay off all debt in <3 years = excellent
    if (debtPaydownCapacity > 0.33) efficiencySignals.push(95);
    else if (debtPaydownCapacity > 0.20) efficiencySignals.push(85);
    else if (debtPaydownCapacity > 0.10) efficiencySignals.push(70);
    else if (debtPaydownCapacity > 0) efficiencySignals.push(50);
    else efficiencySignals.push(25);
    // Only log years if capacity is positive (avoid division by zero)
    if (debtPaydownCapacity > 0) {
      console.log(`[healthScore] Debt paydown capacity: ${debtPaydownCapacity.toFixed(2)} (pay off in ${(1 / debtPaydownCapacity).toFixed(1)} years)`);
    } else {
      console.log(`[healthScore] Debt paydown capacity: 0 (negative or zero operating cash flow)`);
    }
  }

  if (efficiencySignals.length > 0) {
    scores.efficiency = Math.round(
      efficiencySignals.reduce((a, b) => a + b) / efficiencySignals.length
    );
  }

  // Calculate weighted overall score (enhanced weights)
  // Profitability (25%) + Cash Flow Quality (25%) + Leverage (20%) + Growth (20%) + Efficiency (10%)
  let overallScore = Math.round(
    (scores.profitability * 0.25 +
      scores.cashFlowQuality * 0.25 +
      scores.leverage * 0.20 +
      scores.growth * 0.20 +
      scores.efficiency * 0.10)
  );

  console.log(`[healthScore] Component scores:`, {
    profitability: scores.profitability,
    cashFlowQuality: scores.cashFlowQuality,
    leverage: scores.leverage,
    growth: scores.growth,
    efficiency: scores.efficiency,
    overallBeforeCashRunway: overallScore
  });

  // CRITICAL: Apply severe penalty if cash runway is critically low
  if (cashRunway !== null && cashRunway !== undefined) {
    if (cashRunway < 12) {
      // Critical situation: cap score at 40 max
      console.log(`[healthScore] CRITICAL CASH RUNWAY: ${cashRunway} months - capping at 40`);
      overallScore = Math.min(overallScore, 40);
    } else if (cashRunway < 24) {
      // High risk: cap score at 55 max
      console.log(`[healthScore] LOW CASH RUNWAY: ${cashRunway} months - capping at 55`);
      overallScore = Math.min(overallScore, 55);
    }
  }

  console.log(`[healthScore] FINAL SCORE: ${overallScore}`);

  return {
    overall: overallScore,
    scores: scores,
    interpretation: getHealthInterpretation(overallScore)
  };
}

// Helper: Generate interpretation text with enhanced insights
function getHealthInterpretation(score) {
  if (score >= 85) {
    return {
      rating: 'Excellent',
      color: '#22c55e',
      summary: 'Exceptional financial health. Strong profitability, robust cash generation, manageable debt, and positive growth momentum.'
    };
  } else if (score >= 75) {
    return {
      rating: 'Very Good',
      color: '#84cc16',
      summary: 'Strong financial position with solid profitability and cash flow. Company is managing growth well.'
    };
  } else if (score >= 65) {
    return {
      rating: 'Good',
      color: '#8fdf7d',
      summary: 'Generally healthy financials. Profitability and cash flow are adequate with manageable risks.'
    };
  } else if (score >= 55) {
    return {
      rating: 'Fair',
      color: '#fbbf24',
      summary: 'Mixed financial signals. Company has adequate fundamentals but monitor closely for weakening trends.'
    };
  } else if (score >= 45) {
    return {
      rating: 'Weak',
      color: '#f97316',
      summary: 'Notable financial challenges. Profitability or cash flow concerns require attention.'
    };
  } else if (score >= 30) {
    return {
      rating: 'Poor',
      color: '#fb923c',
      summary: 'Significant financial stress. Multiple warning signs including losses, cash burn, or high debt levels.'
    };
  } else {
    return {
      rating: 'Critical',
      color: '#ef4444',
      summary: 'Severe financial distress. Immediate attention required to address profitability, cash flow, or solvency issues.'
    };
  }
}

// Generate AI insights about financial health
async function generateHealthInsights(ticker, formType, metrics, healthScore) {
  try {
    if (!healthScore) return null;

    const prompt = `You are explaining a company's financial health to someone who isn't a financial expert. Make it simple and easy to understand. Keep it to 2-3 sentences max.

Company: ${ticker}
Overall Health Score: ${healthScore.overall}/100 (${healthScore.interpretation.rating})

The company's scorecard:
- Profitability (making money): ${Math.round(healthScore.scores.profitability)}/100
- Cash Flow (money in the bank): ${Math.round(healthScore.scores.cashFlowQuality)}/100
- Debt (money they owe): ${Math.round(healthScore.scores.leverage)}/100
- Growth (getting bigger): ${Math.round(healthScore.scores.growth)}/100
- Efficiency (using resources well): ${Math.round(healthScore.scores.efficiency)}/100

Key numbers:
- Revenue: $${metrics.revenue ? metrics.revenue.toFixed(1) : 'N/A'}B
- Net Income (profit): $${metrics.netIncome ? metrics.netIncome.toFixed(1) : 'N/A'}B
- Cash from operations: $${metrics.operatingCashFlow ? metrics.operatingCashFlow.toFixed(1) : 'N/A'}B
- Total debt: $${metrics.liabilities ? metrics.liabilities.toFixed(1) : 'N/A'}B

In plain English: What's the overall financial picture? What's working well, and what should investors watch?`;

    const response = await anthropic.messages.create({
      model: 'claude-opus-4-8',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }]
    });

    const insight = response.content[0].type === 'text' ? response.content[0].text : null;
    console.log(`[healthInsights] Generated for ${ticker}: ${insight?.substring(0, 50)}...`);
    return insight;
  } catch (err) {
    console.error(`[healthInsights] Error generating insights for ${ticker}:`, err.message);
    return null;
  }
}

// Analyze debt structure: short-term vs long-term with maturity concentration
function analyzeDebtStructure(metrics) {
  const analysis = {
    shortTermDebt: null,
    longTermDebt: null,
    totalDebt: metrics.liabilities || null,
    shortTermRatio: null,
    longTermRatio: null,
    refinancingRisk: 'low', // default assumption
    maturityConcentration: null,
    debtMaturityRisk: 'low'
  };

  // If we have current liabilities, use as proxy for short-term debt
  if (metrics.currentLiabilities && metrics.liabilities) {
    analysis.shortTermDebt = metrics.currentLiabilities;
    analysis.longTermDebt = Math.max(0, metrics.liabilities - metrics.currentLiabilities);

    if (metrics.liabilities > 0) {
      analysis.shortTermRatio = (metrics.currentLiabilities / metrics.liabilities * 100).toFixed(1);
      analysis.longTermRatio = (analysis.longTermDebt / metrics.liabilities * 100).toFixed(1);

      // Flag high short-term debt (>40% of total debt due within 1 year)
      if (metrics.currentLiabilities / metrics.liabilities > 0.4) {
        analysis.refinancingRisk = 'high';
      } else if (metrics.currentLiabilities / metrics.liabilities > 0.25) {
        analysis.refinancingRisk = 'moderate';
      }

      // Debt maturity concentration risk (if >50% due in next 2 years = risky)
      // Approximate: assume next 2 years = ~2x current liabilities + half of long-term
      const debtNextTwoYears = metrics.currentLiabilities + (analysis.longTermDebt * 0.25);
      analysis.maturityConcentration = (debtNextTwoYears / metrics.liabilities * 100).toFixed(1);

      if (debtNextTwoYears / metrics.liabilities > 0.5) {
        analysis.debtMaturityRisk = 'high';
      } else if (debtNextTwoYears / metrics.liabilities > 0.35) {
        analysis.debtMaturityRisk = 'moderate';
      }
    }
  }

  return analysis;
}

// Helper: Calculate cash runway and red flags for transparency
function calculateCashRunwayAndFlags(metrics) {
  const flags = {
    redFlags: [],
    cashRunway: null,
    riskLevel: 'moderate'
  };

  // Calculate monthly burn rate from operating cash flow
  if (metrics.operatingCashFlow !== null && metrics.operatingCashFlow !== undefined) {
    const monthlyCashFlow = metrics.operatingCashFlow / 12;

    // Negative OCF = cash burn (pre-revenue or distressed companies)
    if (monthlyCashFlow < 0) {
      const monthlyBurn = Math.abs(monthlyCashFlow);

      // Estimate cash on hand (most accurate to least accurate):
      // 1. Current assets minus current liabilities (working capital)
      // 2. 30% of current assets as proxy for cash equivalents
      let cashOnHand = 0;
      if (metrics.currentAssets && metrics.currentLiabilities) {
        // Conservative: assume excess current assets are available as cash
        cashOnHand = Math.max(0, metrics.currentAssets - metrics.currentLiabilities);
      } else if (metrics.currentAssets) {
        cashOnHand = metrics.currentAssets * 0.3; // Fallback: 30% of current assets
      }

      // Calculate runway in months
      if (cashOnHand > 0 && monthlyBurn > 0) {
        flags.cashRunway = Math.round(cashOnHand / monthlyBurn);

        if (flags.cashRunway < 12) {
          flags.redFlags.push(`⚠️ Critical: Only ${flags.cashRunway} months of cash at current burn rate`);
          flags.riskLevel = 'critical';
        } else if (flags.cashRunway < 24) {
          flags.redFlags.push(`⚠️ Warning: ${flags.cashRunway} months of cash runway - monitor closely`);
          flags.riskLevel = 'high';
        }
      }

      flags.redFlags.push('🔴 Negative Operating Cash Flow - Company is burning cash');
    }
  }

  // Red flag: Negative net income
  if (metrics.netIncome !== null && metrics.netIncome !== undefined && metrics.netIncome < 0) {
    flags.redFlags.push('🔴 Negative Net Income - Operating at a loss');
  }

  // Red flag: High debt-to-equity
  if (metrics.liabilities && metrics.equity) {
    const debtToEquity = metrics.liabilities / (metrics.equity || 1);
    if (debtToEquity > 2) {
      flags.redFlags.push('🔴 High leverage - Debt-to-Equity > 2.0');
    }
  }

  // Red flag: Low current ratio (liquidity)
  if (metrics.currentAssets && metrics.currentLiabilities) {
    const currentRatio = metrics.currentAssets / metrics.currentLiabilities;
    if (currentRatio < 1) {
      flags.redFlags.push('🔴 Poor liquidity - Current Ratio < 1.0');
    }
  }

  // Red flag: Deteriorating profitability (negative margins)
  if (metrics.netIncome && metrics.revenue && metrics.revenue > 0) {
    const netMargin = (metrics.netIncome / metrics.revenue) * 100;
    if (netMargin < -5) {
      flags.redFlags.push('🔴 Severe losses - Net margin < -5%');
    }
  }

  // Red flag: Very low or negative operating margins
  if (metrics.operatingIncome && metrics.revenue && metrics.revenue > 0) {
    const opMargin = (metrics.operatingIncome / metrics.revenue) * 100;
    if (opMargin < -5) {
      flags.redFlags.push('🔴 Operating loss - Operating margin < -5%');
    } else if (opMargin < 0 && opMargin >= -5) {
      flags.redFlags.push('⚠️ Operating at a loss - Operating margin negative');
    }
  }

  // Red flag: Poor return on assets (inefficient use of assets)
  if (metrics.netIncome && metrics.totalAssets && metrics.totalAssets > 0) {
    const roa = (metrics.netIncome / metrics.totalAssets) * 100;
    if (roa < 2) {
      flags.redFlags.push('⚠️ Low returns on assets - ROA < 2% (inefficient asset usage)');
    }
  }

  // Red flag: Poor return on invested capital
  if (metrics.operatingIncome && metrics.equity && metrics.liabilities) {
    const investedCapital = metrics.equity + metrics.liabilities;
    if (investedCapital > 0) {
      const roic = (metrics.operatingIncome / investedCapital) * 100;
      if (roic < 5) {
        flags.redFlags.push('⚠️ Low ROIC - Less than 5% return on capital deployed');
      }
    }
  }

  // Red flag: High short-term debt refinancing risk
  if (metrics.currentLiabilities && metrics.liabilities) {
    const shortTermRatio = metrics.currentLiabilities / metrics.liabilities;
    if (shortTermRatio > 0.4) {
      flags.redFlags.push('⚠️ Refinancing risk - Over 40% of debt due within 1 year');
    }
  }

  // Yellow flag: Very high tax rate (may indicate one-time items or unusual tax situations)
  if (metrics.operatingIncome && metrics.netIncome && metrics.operatingIncome > 0) {
    const estimatedTax = metrics.operatingIncome - metrics.netIncome;
    if (estimatedTax > 0) {
      const effectiveTaxRate = (estimatedTax / metrics.operatingIncome) * 100;
      if (effectiveTaxRate > 40) {
        flags.redFlags.push('⚠️ High tax rate - Over 40% (check for one-time tax items)');
      }
    }
  }

  // Red flag: High accruals ratio (earnings quality concern)
  // High accruals = net income not converting to operating cash flow
  if (metrics.netIncome && metrics.operatingCashFlow && metrics.totalAssets && metrics.totalAssets > 0) {
    const accruals = metrics.netIncome - metrics.operatingCashFlow;
    const accrualsRatio = (accruals / metrics.totalAssets) * 100;
    if (accrualsRatio > 10) {
      flags.redFlags.push('⚠️ Earnings quality concern - High accruals (>10% of assets)');
    }
  }

  // Red flag: Negative working capital (potential liquidity issue)
  if (metrics.currentAssets && metrics.currentLiabilities) {
    const workingCapital = metrics.currentAssets - metrics.currentLiabilities;
    if (workingCapital < 0) {
      flags.redFlags.push('🔴 Negative working capital - Current liabilities exceed current assets');
      flags.riskLevel = 'critical';
    }
  }

  // Yellow flag: High working capital as % of revenue (capital inefficiency)
  if (metrics.currentAssets && metrics.currentLiabilities && metrics.revenue && metrics.revenue > 0) {
    const workingCapital = metrics.currentAssets - metrics.currentLiabilities;
    const wcPercent = (workingCapital / metrics.revenue) * 100;
    // Flag if >30% of revenue tied up in working capital
    if (wcPercent > 30) {
      flags.redFlags.push('⚠️ Working capital inefficiency - Over 30% of revenue tied up');
    }
  }

  // Red flag: High debt maturity concentration risk
  if (metrics.currentLiabilities && metrics.liabilities && metrics.liabilities > 0) {
    const debtNextTwoYears = metrics.currentLiabilities + (Math.max(0, metrics.liabilities - metrics.currentLiabilities) * 0.25);
    const maturityConcentration = debtNextTwoYears / metrics.liabilities;
    if (maturityConcentration > 0.5) {
      flags.redFlags.push('⚠️ Debt maturity risk - Over 50% of debt due within 2 years');
    }
  }

  // Yellow flag: High operating expense ratio (>80% of revenue spent on operations)
  if (metrics.revenue && metrics.operatingIncome && metrics.revenue > 0) {
    const opExpenseRatio = ((metrics.revenue - metrics.operatingIncome) / metrics.revenue) * 100;
    if (opExpenseRatio > 80) {
      flags.redFlags.push('⚠️ High operating expenses - Over 80% of revenue consumed by operations');
    }
  }

  // Yellow flag: Low FCF conversion (FCF < 50% of Net Income = earnings not converting well)
  if (metrics.freeCashFlow && metrics.netIncome && metrics.netIncome > 0) {
    const fcfConversion = metrics.freeCashFlow / metrics.netIncome;
    if (fcfConversion < 0.5 && fcfConversion > 0) {
      flags.redFlags.push('⚠️ Low FCF conversion - Free cash flow is less than 50% of net income');
    }
  }

  // Yellow flag: Very high CapEx intensity (>30% of revenue = capital intensive)
  if (metrics.capex && metrics.revenue && metrics.revenue > 0) {
    const capexIntensity = (Math.abs(metrics.capex) / metrics.revenue) * 100;
    if (capexIntensity > 30) {
      flags.redFlags.push('⚠️ High capital intensity - CapEx exceeds 30% of revenue');
    }
  }

  // Red flag: Unsustainable net debt relative to FCF (>5 years to payoff)
  if (metrics.liabilities && metrics.currentAssets && metrics.freeCashFlow && metrics.freeCashFlow > 0) {
    const netDebt = Math.max(0, metrics.liabilities - metrics.currentAssets);
    const debtPayoffYears = netDebt / metrics.freeCashFlow;
    if (debtPayoffYears > 5) {
      flags.redFlags.push('⚠️ High net debt burden - Over 5 years of FCF needed to pay off net debt');
    }
  }

  // Yellow flag: Low return on CapEx (<2x = poor capital efficiency)
  if (metrics.operatingIncome && metrics.capex && Math.abs(metrics.capex) > 0) {
    const returnOnCapex = metrics.operatingIncome / Math.abs(metrics.capex);
    if (returnOnCapex < 2 && returnOnCapex > 0) {
      flags.redFlags.push('⚠️ Low CapEx returns - Operating income less than 2x annual CapEx');
    }
  }

  // Red flag: Declining revenue year-over-year (for context)
  // Note: YoY data needs to come from growthTrends, not available here

  return flags;
}

// Helper: calculate financial ratios
function calculateRatios(metrics) {
  const ratios = {};

  // Profitability Ratios
  if (metrics.netIncome && metrics.equity) {
    ratios.roe = (metrics.netIncome / metrics.equity * 100).toFixed(2); // Return on Equity
  }
  if (metrics.netIncome && metrics.revenue) {
    ratios.profitMargin = (metrics.netIncome / metrics.revenue * 100).toFixed(2); // Net Profit Margin
  }
  if (metrics.operatingIncome && metrics.revenue) {
    ratios.operatingMargin = (metrics.operatingIncome / metrics.revenue * 100).toFixed(2); // Operating Margin
  }
  if (metrics.grossProfit && metrics.revenue) {
    ratios.grossMargin = (metrics.grossProfit / metrics.revenue * 100).toFixed(2); // Gross Profit Margin
  }

  // Liquidity Ratios
  if (metrics.currentAssets && metrics.currentLiabilities) {
    ratios.currentRatio = (metrics.currentAssets / metrics.currentLiabilities).toFixed(2); // Current Ratio
  }

  // Leverage Ratios
  if (metrics.liabilities && metrics.equity) {
    ratios.debtToEquity = (metrics.liabilities / metrics.equity).toFixed(2); // Debt-to-Equity Ratio
  }

  // Interest Coverage Ratio (Operating Income / Interest Expense)
  // Estimate: Use Operating Margin as proxy if interest expense unavailable
  if (metrics.operatingIncome && metrics.revenue) {
    const estimatedInterestExpense = metrics.revenue * 0.02; // Conservative: assume 2% of revenue
    if (estimatedInterestExpense > 0) {
      ratios.interestCoverage = (metrics.operatingIncome / estimatedInterestExpense).toFixed(2);
    }
  }

  // Efficiency Ratios
  if (metrics.revenue && metrics.totalAssets) {
    ratios.assetTurnover = (metrics.revenue / metrics.totalAssets).toFixed(2); // Asset Turnover
  }

  // Return Metrics (Capital Efficiency)
  if (metrics.netIncome && metrics.totalAssets) {
    ratios.roa = (metrics.netIncome / metrics.totalAssets * 100).toFixed(2); // Return on Assets
  }

  // ROIC = EBIT / (Equity + Debt - Cash)
  // Simplified: Using Operating Income as proxy for EBIT
  if (metrics.operatingIncome && metrics.equity && metrics.liabilities) {
    const investedCapital = metrics.equity + metrics.liabilities;
    if (investedCapital > 0) {
      ratios.roic = (metrics.operatingIncome / investedCapital * 100).toFixed(2); // Return on Invested Capital
    }
  }

  // Effective Tax Rate = (Income Before Tax - Net Income) / Income Before Tax
  // Note: SEC filings don't always explicitly state "income before tax" - we estimate it
  // Estimate: If we have operating income and net income, tax burden ≈ (Operating Income - Net Income) / Operating Income
  if (metrics.operatingIncome && metrics.netIncome && metrics.operatingIncome > 0) {
    const estimatedTax = metrics.operatingIncome - metrics.netIncome;
    if (estimatedTax >= 0) {
      const effectiveTaxRate = (estimatedTax / metrics.operatingIncome * 100).toFixed(2);
      ratios.effectiveTaxRate = effectiveTaxRate;
    }
  }

  // Accruals Ratio = (Net Income - Operating Cash Flow) / Total Assets
  // High accruals = earnings quality concern (earnings not converting to cash)
  if (metrics.netIncome && metrics.operatingCashFlow && metrics.totalAssets && metrics.totalAssets > 0) {
    const accruals = metrics.netIncome - metrics.operatingCashFlow;
    ratios.accrualsRatio = (accruals / metrics.totalAssets * 100).toFixed(2);
  }

  // Working Capital Metrics
  if (metrics.currentAssets && metrics.currentLiabilities) {
    ratios.workingCapital = (metrics.currentAssets - metrics.currentLiabilities).toFixed(2);
    ratios.workingCapitalRatio = (metrics.currentAssets / metrics.currentLiabilities).toFixed(2);
  }

  // Working Capital as % of Revenue (efficiency metric)
  if (metrics.currentAssets && metrics.currentLiabilities && metrics.revenue && metrics.revenue > 0) {
    const workingCapital = metrics.currentAssets - metrics.currentLiabilities;
    ratios.workingCapitalPercent = (workingCapital / metrics.revenue * 100).toFixed(2);
  }

  // 8. OPERATING EFFICIENCY METRICS
  // Operating Expense Ratio (Operating Expenses / Revenue) - lower is better
  if (metrics.revenue && metrics.operatingIncome && metrics.revenue > 0) {
    const operatingExpenses = metrics.revenue - metrics.operatingIncome;
    ratios.operatingExpenseRatio = (operatingExpenses / metrics.revenue * 100).toFixed(2);
  }

  // 9. FREE CASH FLOW QUALITY METRICS
  // FCF Conversion Rate (FCF / Net Income) - how much profit converts to free cash
  if (metrics.freeCashFlow && metrics.netIncome && metrics.netIncome > 0) {
    ratios.fcfConversionRate = (metrics.freeCashFlow / metrics.netIncome).toFixed(2);
  }

  // FCF Yield (FCF / Total Assets) - cash generation relative to asset base
  if (metrics.freeCashFlow && metrics.totalAssets && metrics.totalAssets > 0) {
    ratios.fcfYield = (metrics.freeCashFlow / metrics.totalAssets * 100).toFixed(2);
  }

  // CapEx Intensity (CapEx / Revenue) - how capital intensive the business is
  if (metrics.capex && metrics.revenue && metrics.revenue > 0) {
    const capexIntensity = (Math.abs(metrics.capex) / metrics.revenue * 100);
    ratios.capexIntensity = capexIntensity.toFixed(2);
  }

  // 10. ASSET QUALITY METRICS
  // Note: Goodwill and Intangibles require additional extraction from balance sheet
  // For now, we'll calculate with available data

  // 11. LEVERAGE QUALITY - Net Debt Analysis
  // Net Debt = Total Liabilities - Current Assets (conservative estimate)
  if (metrics.liabilities && metrics.currentAssets) {
    const netDebt = Math.max(0, metrics.liabilities - metrics.currentAssets);
    ratios.netDebt = netDebt.toFixed(2);

    // Net Debt / Free Cash Flow (years to pay off net debt)
    if (metrics.freeCashFlow && metrics.freeCashFlow > 0) {
      ratios.netDebtToFCF = (netDebt / metrics.freeCashFlow).toFixed(2);
    }
  }

  // 12. DEPRECIATION & AMORTIZATION (estimated)
  // Estimate D&A from: Gross Profit - Operating Income (when cost structure allows)
  // Note: This is an approximation; actual D&A requires separate extraction
  if (metrics.grossProfit && metrics.operatingIncome && metrics.grossProfit > metrics.operatingIncome) {
    const estimatedDA = metrics.grossProfit - metrics.operatingIncome;
    if (metrics.revenue && metrics.revenue > 0) {
      ratios.daToRevenue = (estimatedDA / metrics.revenue * 100).toFixed(2);
    }
  }

  // 13. CAPITAL EFFICIENCY - Return on CapEx
  // Operating Income / CapEx (how much profit per dollar of capital spent)
  if (metrics.operatingIncome && metrics.capex && Math.abs(metrics.capex) > 0) {
    ratios.returnOnCapex = (metrics.operatingIncome / Math.abs(metrics.capex)).toFixed(2);
  }

  return ratios;
}

// Calculate growth trends by comparing current year to prior year metrics
function calculateGrowthTrends(currentMetrics, priorMetrics) {
  const trends = {
    revenueGrowth: null,
    netIncomeGrowth: null,
    operatingIncomeGrowth: null,
    assetGrowth: null,
    grossMarginChange: null,
    operatingMarginChange: null,
    netMarginChange: null,
    hasData: false
  };

  if (!priorMetrics) return trends;

  // Revenue growth
  if (currentMetrics.revenue && priorMetrics.revenue) {
    trends.revenueGrowth = ((currentMetrics.revenue - priorMetrics.revenue) / priorMetrics.revenue * 100).toFixed(2);
    trends.hasData = true;
  }

  // Net income growth
  if (currentMetrics.netIncome && priorMetrics.netIncome) {
    trends.netIncomeGrowth = ((currentMetrics.netIncome - priorMetrics.netIncome) / priorMetrics.netIncome * 100).toFixed(2);
  }

  // Operating income growth
  if (currentMetrics.operatingIncome && priorMetrics.operatingIncome) {
    trends.operatingIncomeGrowth = ((currentMetrics.operatingIncome - priorMetrics.operatingIncome) / priorMetrics.operatingIncome * 100).toFixed(2);
  }

  // Asset growth
  if (currentMetrics.totalAssets && priorMetrics.totalAssets) {
    trends.assetGrowth = ((currentMetrics.totalAssets - priorMetrics.totalAssets) / priorMetrics.totalAssets * 100).toFixed(2);
  }

  // Margin changes (percentage point change)
  if (currentMetrics.grossProfit && currentMetrics.revenue && priorMetrics.grossProfit && priorMetrics.revenue) {
    const currentGrossMargin = currentMetrics.grossProfit / currentMetrics.revenue * 100;
    const priorGrossMargin = priorMetrics.grossProfit / priorMetrics.revenue * 100;
    trends.grossMarginChange = (currentGrossMargin - priorGrossMargin).toFixed(2);
  }

  if (currentMetrics.operatingIncome && currentMetrics.revenue && priorMetrics.operatingIncome && priorMetrics.revenue) {
    const currentOpMargin = currentMetrics.operatingIncome / currentMetrics.revenue * 100;
    const priorOpMargin = priorMetrics.operatingIncome / priorMetrics.revenue * 100;
    trends.operatingMarginChange = (currentOpMargin - priorOpMargin).toFixed(2);
  }

  if (currentMetrics.netIncome && currentMetrics.revenue && priorMetrics.netIncome && priorMetrics.revenue) {
    const currentNetMargin = currentMetrics.netIncome / currentMetrics.revenue * 100;
    const priorNetMargin = priorMetrics.netIncome / priorMetrics.revenue * 100;
    trends.netMarginChange = (currentNetMargin - priorNetMargin).toFixed(2);
  }

  return trends;
}

// Helper: Find most recent filing for a ticker/formType
app.get('/api/latest-filing/:ticker/:formType', async (req, res) => {
  try {
    const { ticker, formType } = req.params;
    console.log(`[latest-filing] Searching for ${ticker} ${formType}`);

    // Search for company and filings
    const searchUrl = `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=${encodeURIComponent(ticker)}&type=${encodeURIComponent(formType)}&owner=exclude&count=10`;
    console.log(`[latest-filing] Fetching from: ${searchUrl}`);

    const res2 = await fetch(searchUrl, { headers: EDGAR_UA });
    const html = await res2.text();

    // Extract CIK from the page
    const cikMatch = html.match(/\/cgi-bin\/browse-edgar\?action=getcompany&CIK=(\d+)&owner=exclude/);
    if (!cikMatch) {
      console.log('[latest-filing] Could not extract CIK');
      return res.status(404).json({ error: 'Company not found' });
    }

    const cik = cikMatch[1];
    console.log(`[latest-filing] Found CIK: ${cik}`);

    // Extract most recent accession number (format: 0001234567-89-012345)
    const accessionMatch = html.match(/(\d{10}-\d{2}-\d{6})/);
    if (!accessionMatch) {
      console.log('[latest-filing] Could not extract accession');
      return res.status(404).json({ error: `No ${formType} filings found for ${ticker}` });
    }

    const accession = accessionMatch[1];
    console.log(`[latest-filing] Found accession: ${accession}`);

    res.json({ cik, accession, ticker: ticker.toUpperCase(), formType });
  } catch (err) {
    console.error('[latest-filing] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Fetch prior year XBRL metrics for growth calculation
async function fetchPriorYearMetrics(cik, accessionNumber, formType) {
  try {
    if (!cik || !accessionNumber) {
      console.log('[fetchPriorYearMetrics] Missing CIK or accession number');
      return null;
    }

    // Only fetch prior year for 10-K and 10-Q
    if (!['10-K', '10-Q'].includes(formType)) {
      return null;
    }

    console.log(`[fetchPriorYearMetrics] Attempting to fetch prior year for CIK=${cik}`);

    // Extract year from accession: format is XXXXXXXXXX-YY-XXXXXX
    const accessionParts = accessionNumber.match(/(\d{10})-(\d{2})-(\d{6})/);

    if (!accessionParts) {
      console.log('[fetchPriorYearMetrics] Could not parse accession number');
      return null;
    }

    const [, cikPart, yearPart, numberPart] = accessionParts;
    const currentYear = parseInt(yearPart);

    // Try multiple years going back (in case filing was delayed)
    const yearsToTry = [
      currentYear - 1,
      currentYear - 2,
      currentYear - 3
    ];

    // Also try a range of filing sequence numbers for each year
    const filingNumbersToTry = [
      '000077', '000078', '000079', '000080', '000081',
      '000076', '000075', '000074', '000073', '000072'
    ];

    console.log(`[fetchPriorYearMetrics] Trying years: ${yearsToTry.join(', ')}`);

    // Try each year and filing number combination
    for (const year of yearsToTry) {
      const yearStr = year.toString().padStart(2, '0');
      for (const filingNum of filingNumbersToTry) {
        const candidateAcc = `${cikPart}-${yearStr}-${filingNum}`;
        try {
          const metrics = await fetchAllXBRLMetrics(cik, candidateAcc);
          if (metrics && (metrics.revenue || metrics.netIncome)) {
            console.log(`[fetchPriorYearMetrics] ✓ Found prior year metrics with accession ${candidateAcc}`);
            return metrics;
          }
        } catch (e) {
          // Try next combination
          continue;
        }
      }
    }

    console.log('[fetchPriorYearMetrics] Could not find prior year metrics after trying multiple combinations');
    return null;
  } catch (err) {
    console.error('[fetchPriorYearMetrics] Error:', err.message);
    return null;
  }
}

// API: Calculate and return financial metrics
app.post('/api/metrics', authMiddleware, async (req, res) => {
  try {
    const { sections, ticker, accessionNumber, cik, formType } = req.body;

    // 10-K/A filings are amendments and don't have traditional financial metrics
    if (formType === '10-K/A') {
      return res.json({
        extractedMetrics: {},
        calculatedRatios: {},
        healthScore: null,
        cashRunway: null,
        riskLevel: null,
        redFlags: [],
        balanceSheetValid: null,
        balanceSheetSource: 'N/A - Amendment filing',
        message: '10-K/A filings are amendments and do not contain traditional financial metrics. Review the amendment sections for correction details.',
        timestamp: new Date().toISOString()
      });
    }

    // 8-K filings are event reports and don't have traditional financial metrics
    if (formType === '8-K') {
      return res.json({
        extractedMetrics: {},
        calculatedRatios: {},
        healthScore: null,
        cashRunway: null,
        riskLevel: null,
        redFlags: [],
        balanceSheetValid: null,
        balanceSheetSource: 'N/A - Event report',
        message: '8-K filings report material events (earnings, mergers, leadership changes, etc.) and do not contain comprehensive financial statements. Review the event sections for details on what happened.',
        timestamp: new Date().toISOString()
      });
    }

    // DEF 14A filings are proxy statements and don't have traditional financial metrics
    if (formType === 'DEF 14A') {
      return res.json({
        extractedMetrics: {},
        calculatedRatios: {},
        healthScore: null,
        cashRunway: null,
        riskLevel: null,
        redFlags: [],
        balanceSheetValid: null,
        balanceSheetSource: 'N/A - Proxy statement',
        message: 'DEF 14A proxy statements contain shareholder voting information, executive compensation, and governance details — not comprehensive financial statements. Review the governance and compensation sections.',
        timestamp: new Date().toISOString()
      });
    }

    // 13-F filings are fund holdings reports and don't have traditional financial metrics
    if (formType === '13-F') {
      return res.json({
        extractedMetrics: {},
        calculatedRatios: {},
        healthScore: null,
        cashRunway: null,
        riskLevel: null,
        redFlags: [],
        balanceSheetValid: null,
        balanceSheetSource: 'N/A - Holdings report',
        message: '13-F filings report portfolio holdings and changes for institutional investors. They do not contain the filing company\'s traditional financial statements. Review the holdings and portfolio change sections.',
        timestamp: new Date().toISOString()
      });
    }

    // Extract figures from sections (profitability, efficiency, liquidity)
    const metrics = extractMetricsFromSections(sections || {});
    console.log('[/api/metrics] Sections received:', Object.keys(sections || {}));
    console.log('[/api/metrics] Extracted metrics:', {
      revenue: metrics.revenue,
      netIncome: metrics.netIncome,
      operatingIncome: metrics.operatingIncome,
      grossProfit: metrics.grossProfit,
      totalLiabilities: metrics.totalLiabilities,
      totalAssets: metrics.totalAssets,
      equity: metrics.equity
    });

    // Check if we got empty metrics and log warning
    if (!metrics.netIncome && !metrics.revenue) {
      console.warn('[/api/metrics] ⚠️ No metrics extracted! Sections might be empty or missing key_figures');
      console.log('[/api/metrics] First section sample:', sections[Object.keys(sections)[0]]);
    }

    // Try to fetch and use XBRL data for accuracy (10-K, 10-Q, 20-F)
    let xbrlMetrics = null;
    const xbrlSupportedForms = ['10-K', '10-Q', '20-F'];
    if (xbrlSupportedForms.includes(req.body.formType) && cik && accessionNumber) {
      xbrlMetrics = await fetchAllXBRLMetrics(cik, accessionNumber);
      if (xbrlMetrics) {
        console.log(`[metrics] Using XBRL data for ${req.body.formType}`);
        // Override metrics with XBRL data (more reliable)
        // Profitability metrics
        metrics.revenue = xbrlMetrics.revenue || metrics.revenue;
        metrics.netIncome = xbrlMetrics.netIncome || metrics.netIncome;
        metrics.operatingIncome = xbrlMetrics.operatingIncome || metrics.operatingIncome;
        metrics.grossProfit = xbrlMetrics.grossProfit || metrics.grossProfit;
        // Efficiency/Cashflow metrics
        metrics.operatingCashFlow = xbrlMetrics.operatingCashFlow || metrics.operatingCashFlow;
        metrics.capex = xbrlMetrics.capex || metrics.capex;
        metrics.freeCashFlow = xbrlMetrics.freeCashFlow || metrics.freeCashFlow;
        // Balance sheet metrics
        metrics.totalAssets = xbrlMetrics.totalAssets || metrics.totalAssets;
        metrics.currentAssets = xbrlMetrics.currentAssets || metrics.currentAssets;
        metrics.totalLiabilities = xbrlMetrics.totalLiabilities || metrics.totalLiabilities;
        metrics.currentLiabilities = xbrlMetrics.currentLiabilities || metrics.currentLiabilities;
        metrics.liabilities = xbrlMetrics.totalLiabilities || metrics.liabilities;
        metrics.equity = xbrlMetrics.equity || metrics.equity;
      }
    }

    // Fallback: If net income still missing and we have filing details, try direct HTML search
    if (!metrics.netIncome && cik && accessionNumber && xbrlSupportedForms.includes(req.body.formType)) {
      try {
        const { text: filingText } = await fetchFilingText(cik, accessionNumber, req.body.primaryDocument || '', req.body.formType);
        if (filingText) {
          console.log(`[metrics] Attempting direct filing text search for net income...`);
          // Search for net income in table format: "Net income | ... | 3794" or similar
          const netIncomeMatch = filingText.match(/net\s+income[^0-9]*?([0-9,]+)\s*[0-9,]*(?:\s|$)/i);
          if (netIncomeMatch) {
            const value = parseFloat(netIncomeMatch[1].replace(/,/g, ''));
            if (value > 0 && value < 1000000) { // Sanity check: should be reasonable size
              metrics.netIncome = value;
              console.log(`[metrics] Found net income from filing text: ${metrics.netIncome}`);
            }
          }
        }
      } catch (err) {
        console.error(`[metrics] Failed to fetch filing text for net income search:`, err.message);
      }
    }

    // Log extracted metrics for debugging
    console.log(`[/api/metrics] ${ticker} ${formType} - Extracted metrics:`);
    console.log(`  revenue: ${metrics.revenue}`);
    console.log(`  netIncome: ${metrics.netIncome}`);
    console.log(`  operatingIncome: ${metrics.operatingIncome}`);
    console.log(`  grossProfit: ${metrics.grossProfit}`);
    console.log(`  totalAssets: ${metrics.totalAssets}`);
    console.log(`  currentAssets: ${metrics.currentAssets}`);
    console.log(`  totalLiabilities: ${metrics.totalLiabilities}`);
    console.log(`  currentLiabilities: ${metrics.currentLiabilities}`);
    console.log(`  equity: ${metrics.equity}`);
    console.log(`  operatingCashFlow: ${metrics.operatingCashFlow}`);
    console.log(`  capex: ${metrics.capex}`);
    console.log(`  freeCashFlow: ${metrics.freeCashFlow}`);

    // Validate balance sheet equation: Assets = Liabilities + Equity
    const balanceSheetValid = validateBalanceSheet(metrics);

    // Calculate ratios (includes ROA, ROIC, effective tax rate)
    const ratios = calculateRatios(metrics);

    // Log which ratios were calculated
    console.log(`[/api/metrics] ${ticker} ${formType} - Calculated ratios:`);
    console.log(`  roa: ${ratios.roa || 'NOT CALCULATED'} (needs: netIncome=${metrics.netIncome}, totalAssets=${metrics.totalAssets})`);
    console.log(`  roic: ${ratios.roic || 'NOT CALCULATED'} (needs: operatingIncome=${metrics.operatingIncome}, equity=${metrics.equity}, liabilities=${metrics.liabilities})`);
    console.log(`  fcfConversionRate: ${ratios.fcfConversionRate || 'NOT CALCULATED'} (needs: freeCashFlow=${metrics.freeCashFlow}, netIncome=${metrics.netIncome})`);
    console.log(`  fcfYield: ${ratios.fcfYield || 'NOT CALCULATED'} (needs: freeCashFlow=${metrics.freeCashFlow}, totalAssets=${metrics.totalAssets})`);
    console.log(`  debtToEquity: ${ratios.debtToEquity || 'NOT CALCULATED'} (needs: liabilities=${metrics.liabilities}, equity=${metrics.equity})`);

    // Analyze debt structure (short-term vs long-term)
    const debtAnalysis = analyzeDebtStructure(metrics);

    // Calculate cash runway and red flags for transparency
    const cashRunwayFlags = calculateCashRunwayAndFlags(metrics);

    // PHASE 2: Disabled for now - prior year fetch was causing performance issues
    // TODO: Implement robust multi-year data fetching with caching before re-enabling
    let growthTrends = null;

    // Check if core metrics are missing or all zero (indicates extraction failure)
    const hasRevenue = metrics.revenue && metrics.revenue !== 0;
    const hasNetIncome = metrics.netIncome && metrics.netIncome !== 0;
    const hasCashFlow = metrics.operatingCashFlow && metrics.operatingCashFlow !== 0;
    const hasAssets = metrics.totalAssets && metrics.totalAssets !== 0;

    const metricsExtracted = hasRevenue || hasNetIncome || hasAssets;

    // If we have balance sheet data but NO income/cashflow, might be a financial institution
    const isFinancialInstitution = hasAssets && !hasRevenue && !hasNetIncome && !hasCashFlow;

    // Calculate health score (with cash runway penalty)
    const healthScore = metricsExtracted && !isFinancialInstitution ? calculateHealthScore(metrics, ratios, cashRunwayFlags.cashRunway, growthTrends) : null;

    // Generate AI insights about financial health
    let healthInsights = null;
    if (healthScore) {
      healthInsights = await generateHealthInsights(req.body.ticker, req.body.formType, metrics, healthScore);
    }

    // Check which key metrics are missing
    const missingMetrics = [];
    if (!metrics.netIncome && (ratios.roa === undefined || ratios.fcfConversionRate === undefined)) {
      missingMetrics.push('Net Income (required for ROA and FCF Conversion Rate)');
    }

    // If core metrics are unavailable or it's a financial institution, provide a helpful message
    let message = null;
    if (!metricsExtracted || isFinancialInstitution) {
      message = `Financial metrics could not be extracted from this ${req.body.formType} filing. This commonly occurs for financial institutions and brokerages that use non-standard reporting formats. Please refer to the original SEC filing for detailed financial information.`;
    } else if (missingMetrics.length > 0) {
      message = `Some metrics are not available: ${missingMetrics.join(', ')}. This can occur if the filing uses non-standard formats or if the data is presented in tables that couldn't be extracted. Other available metrics are displayed above.`;
    }

    // Store metrics history if we extracted valid metrics
    if (metricsExtracted && healthScore) {
      try {
        // Construct filing URL from CIK, accession number, and primary document
        const numericCik = cik.replace(/^0+/, '');
        const cleanAcc = accessionNumber.replace(/-/g, '');
        const base = `https://www.sec.gov/Archives/edgar/data/${numericCik}/${cleanAcc}`;
        const filingUrl = `${base}/${req.body.primaryDocument || 'index.html'}`;

        // Use today's date as filing date (clients should eventually send actual filing date)
        const today = new Date().toISOString().split('T')[0];

        await storeMetricsHistory(ticker, today, formType, metrics, ratios, healthScore, filingUrl);
        console.log(`[metrics] Stored metrics history for ${ticker} ${today}`);

        // Check and trigger custom alerts for this metric analysis
        const alertMetrics = {
          health_score: healthScore,
          revenue: metrics.revenue,
          net_income: metrics.netIncome,
          operating_income: metrics.operatingIncome,
          operating_cash_flow: metrics.operatingCashFlow,
          free_cash_flow: metrics.freeCashFlow,
          current_ratio: ratios.currentRatio,
          quick_ratio: ratios.quickRatio,
          debt_to_equity: ratios.debtToEquity,
          roa: ratios.roa,
          roic: ratios.roic,
          fcf_yield: ratios.fcfYield
        };
        await checkAndTriggerAlerts(ticker, alertMetrics);
      } catch (err) {
        console.error(`[metrics] Failed to store metrics history: ${err.message}`);
        // Don't fail the response if storage fails
      }
    }

    // Create metrics availability summary
    const metricsAvailability = {
      revenue: !!metrics.revenue,
      netIncome: !!metrics.netIncome,
      operatingIncome: !!metrics.operatingIncome,
      grossProfit: !!metrics.grossProfit,
      totalAssets: !!metrics.totalAssets,
      operatingCashFlow: !!metrics.operatingCashFlow,
      freeCashFlow: !!metrics.freeCashFlow,
      equity: !!metrics.equity,
      liabilities: !!metrics.liabilities,
      capex: !!metrics.capex
    };

    // Calculate how many ratios are available
    const ratiosAvailable = Object.values(ratios).filter(v => v !== undefined && v !== null).length;

    res.json({
      extractedMetrics: metrics,
      calculatedRatios: ratios,
      debtAnalysis: debtAnalysis,
      healthScore: healthScore,
      healthInsights: healthInsights,
      cashRunway: cashRunwayFlags.cashRunway,
      riskLevel: cashRunwayFlags.riskLevel,
      redFlags: cashRunwayFlags.redFlags,
      balanceSheetValid: balanceSheetValid,
      balanceSheetSource: xbrlMetrics ? 'XBRL' : 'extracted',
      growthTrends: growthTrends,
      message: message,
      metricsAvailability: metricsAvailability,
      ratiosAvailable: ratiosAvailable,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Validate that balance sheet equation holds: Assets = Liabilities + Equity (within 5% tolerance)
function validateBalanceSheet(metrics) {
  if (!metrics.totalAssets || !metrics.liabilities || !metrics.equity) {
    return null; // Can't validate if any value is missing
  }

  const assets = metrics.totalAssets;
  const liabilities = metrics.liabilities;
  const equity = metrics.equity;
  const calculatedEquity = assets - liabilities;

  // Allow 5% tolerance for rounding/formatting differences
  const tolerance = assets * 0.05;
  const difference = Math.abs(equity - calculatedEquity);

  const isValid = difference <= tolerance;
  console.log(`[validateBalanceSheet] Assets: ${assets.toFixed(2)}, Liabilities: ${liabilities.toFixed(2)}, Equity: ${equity.toFixed(2)}, Calculated Equity: ${calculatedEquity.toFixed(2)}, Difference: ${difference.toFixed(2)}, Valid: ${isValid}`);

  return isValid;
}

// ── FILING COMPARISONS ────────────────────────────────────────────────────────
app.post('/api/comparisons/filings', authMiddleware, async (req, res) => {
  try {
    const { ticker, formType, analysis1, analysis2, period1, period2 } = req.body;

    // Extract metrics from both analyses
    const metrics1 = extractMetricsFromSections(analysis1?.sections || {});
    const metrics2 = extractMetricsFromSections(analysis2?.sections || {});

    // Calculate changes
    const changes = {};
    const metricKeys = Object.keys(metrics1);

    metricKeys.forEach(key => {
      const val1 = metrics1[key];
      const val2 = metrics2[key];

      if (val1 && val2) {
        const change = val2 - val1;
        const percentChange = ((change / val1) * 100).toFixed(1);
        const direction = change > 0 ? '↑' : change < 0 ? '↓' : '→';

        changes[key] = {
          period1: val1,
          period2: val2,
          change: change.toFixed(2),
          percentChange,
          direction
        };
      }
    });

    // Generate AI commentary on changes
    const changesSummary = Object.entries(changes)
      .map(([key, data]) => `${key}: ${data.direction} ${data.percentChange}% (from ${data.period1} to ${data.period2})`)
      .join('\n');

    const prompt = `Compare these financial metrics between ${period1} and ${period2}:

${changesSummary}

Provide a brief analysis explaining what these changes mean for the company's financial health. Focus on:
1. Most significant changes and their implications
2. Overall trends (improving/declining health)
3. Key concerns if any

Keep it to 2-3 paragraphs in plain English.`;

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 600,
      messages: [{ role: 'user', content: prompt }]
    });

    const commentary = message.content[0].type === 'text' ? message.content[0].text : '';

    res.json({
      ticker,
      formType,
      comparison: {
        period1,
        period2,
        changes,
        aiCommentary: commentary
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── BILLING ───────────────────────────────────────────────────────────────────

app.post('/api/billing/create-checkout-session', authMiddleware, async (req, res) => {
  try {
    if (!process.env.STRIPE_PRICE_ID_PRO) {
      return res.status(400).json({ error: 'Stripe Pro price not configured. Add STRIPE_PRICE_ID_PRO to .env' });
    }

    const user = await db.getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Account not found' });

    const subscription = await db.getSubscriptionByUserId(req.user.id);

    const origin = req.headers.origin || `http://localhost:${PORT}`;
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID_PRO, quantity: 1 }],
      success_url: `${origin}/finread.html?upgrade=success`,
      cancel_url: `${origin}/finread.html?upgrade=cancelled`,
      client_reference_id: user.id,
      ...(subscription?.stripe_customer_id ? { customer: subscription.stripe_customer_id } : { customer_email: user.email }),
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout session error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/billing/create-portal-session', authMiddleware, async (req, res) => {
  try {
    const subscription = await db.getSubscriptionByUserId(req.user.id);
    if (!subscription?.stripe_customer_id) {
      return res.status(400).json({ error: 'No billing account found. Subscribe to Pro first.' });
    }

    const origin = req.headers.origin || `http://localhost:${PORT}`;
    const session = await stripe.billingPortal.sessions.create({
      customer: subscription.stripe_customer_id,
      return_url: `${origin}/finread.html`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe portal session error:', err);
    res.status(500).json({ error: err.message });
  }
});

async function setUserTierByField(field, value, updates) {
  const users = await readJSON(USERS_FILE);
  const idx = users.findIndex(u => u[field] === value);
  if (idx === -1) return false;
  users[idx] = { ...normalizeUser(users[idx]), ...updates };
  await writeJSON(USERS_FILE, users);
  return true;
}

async function handleStripeWebhook(req, res) {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook signature verification failed: ${err.message}` });
  }

  try {
    console.log(`📨 Webhook received: ${event.type}`);
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = session.client_reference_id;
        console.log(`🔔 checkout.session.completed for user ${userId}`);

        // Create or update subscription to 'pro'
        let subscription = await db.getSubscriptionByUserId(userId);
        if (!subscription) {
          await db.createSubscription(userId, session.customer, 'pro');
          console.log(`✅ Subscription created for user ${userId}, customer ${session.customer}, plan: pro`);
        } else {
          // Update existing subscription to pro
          await db.updateSubscription(userId, {
            stripe_subscription_id: session.subscription,
            status: 'active',
            current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // Estimate 30 days
          });
          // Manually update plan_type to pro since updateSubscription doesn't handle it
          await sql`UPDATE subscriptions SET plan_type = 'pro' WHERE user_id = ${userId}`;
          console.log(`✅ Subscription updated to pro for user ${userId}`);
        }
        break;
      }
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const isActive = subscription.status === 'active' || subscription.status === 'trialing';
        const dbSubscription = await db.getSubscriptionByStripeCustomerId(subscription.customer);

        if (dbSubscription) {
          await db.updateSubscription(dbSubscription.user_id, {
            stripe_subscription_id: subscription.id,
            status: isActive ? 'active' : subscription.status,
            current_period_end: new Date(subscription.current_period_end * 1000)
          });
        }
        console.log(`✅ Subscription updated for customer ${subscription.customer}`);
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const dbSubscription = await db.getSubscriptionByStripeCustomerId(subscription.customer);

        if (dbSubscription) {
          await db.cancelSubscription(dbSubscription.user_id, new Date());
        }
        console.log(`✅ Subscription cancelled for customer ${subscription.customer}`);
        break;
      }
    }
    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook handling error:', err);
    res.status(500).json({ error: err.message });
  }
}

// ── PEER BENCHMARKING ENDPOINTS (Phase 5, Task 7) ────────────────────────────

// Helper: Get peers for a company
function getPeersForCompany(ticker) {
  return peerGroups[ticker] || peerGroups.DEFAULT;
}

// Helper: Calculate percentile rank
function calculatePercentile(targetValue, peerValues) {
  if (!peerValues || peerValues.length === 0) return null;

  const sorted = [...peerValues].filter(v => v !== null && v !== undefined).sort((a, b) => a - b);
  if (sorted.length === 0) return null;

  const rank = sorted.filter(v => v < targetValue).length + 1;
  const percentile = Math.round((rank / sorted.length) * 100);
  const median = sorted[Math.floor(sorted.length / 2)];

  return { percentile, rank, median, total: sorted.length };
}

// GET /api/peers/list - Get peer group for a company
app.get('/api/peers/list', authMiddleware, async (req, res) => {
  try {
    const { ticker } = req.query;
    if (!ticker) return res.status(400).json({ error: 'ticker required' });

    const peers = getPeersForCompany(ticker.toUpperCase());
    res.json({
      target: ticker.toUpperCase(),
      peers,
      industry: 'Technology',  // Could be enhanced with actual industry detection
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/peers/compare - Compare target company metrics against peers
app.post('/api/peers/compare', authMiddleware, async (req, res) => {
  try {
    const { targetTicker, peerTickers } = req.body;
    if (!targetTicker) return res.status(400).json({ error: 'targetTicker required' });

    const peers = peerTickers || getPeersForCompany(targetTicker.toUpperCase());

    // Get latest analysis for target
    const targetAnalysis = await getLatestAnalysis(targetTicker.toUpperCase());
    if (!targetAnalysis || !targetAnalysis.calculatedRatios) {
      return res.status(404).json({ error: 'Target company analysis not found' });
    }

    // Get latest analyses for peers
    const peerAnalyses = await Promise.all(
      peers.map(p => getLatestAnalysis(p.toUpperCase()))
    );

    // Calculate comparisons for each metric
    const metricsToCompare = ['roa', 'roic', 'fcf_conversion_rate', 'fcf_yield', 'capex_intensity'];
    const comparison = {};

    for (const metric of metricsToCompare) {
      const targetValue = targetAnalysis.calculatedRatios[metric];
      if (targetValue === undefined) continue;

      const peerValues = peerAnalyses
        .map(p => p?.calculatedRatios?.[metric])
        .filter(v => v !== undefined && v !== null);

      const percentileData = calculatePercentile(targetValue, peerValues);

      comparison[metric] = {
        target: targetValue,
        peers: {},
        percentile: percentileData?.percentile || 0,
        rank: percentileData?.rank || 0,
        median: percentileData?.median || 0,
        status: percentileData?.percentile > 75 ? 'excellent' :
                percentileData?.percentile > 50 ? 'above_average' :
                percentileData?.percentile > 25 ? 'average' : 'below_average'
      };

      // Add peer values
      peers.forEach((peer, idx) => {
        if (peerAnalyses[idx]?.calculatedRatios?.[metric]) {
          comparison[metric].peers[peer] = peerAnalyses[idx].calculatedRatios[metric];
        }
      });
    }

    res.json({
      target: targetTicker.toUpperCase(),
      peers,
      comparison,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Peer comparison error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/peers/rankings - Rank peers for a specific metric
app.get('/api/peers/rankings', authMiddleware, async (req, res) => {
  try {
    const { metric, peers } = req.query;
    if (!metric) return res.status(400).json({ error: 'metric required' });

    const peerList = peers ? peers.split(',') : [];
    if (peerList.length === 0) return res.status(400).json({ error: 'peers required' });

    // Get analyses for all peers
    const analyses = await Promise.all(
      peerList.map(p => getLatestAnalysis(p.toUpperCase()))
    );

    // Extract metric values and rank
    const rankings = analyses
      .map((analysis, idx) => ({
        ticker: peerList[idx].toUpperCase(),
        value: analysis?.calculatedRatios?.[metric] || 0
      }))
      .sort((a, b) => b.value - a.value)
      .map((item, idx) => ({
        rank: idx + 1,
        ticker: item.ticker,
        value: item.value,
        percentile: Math.round(((peerList.length - idx) / peerList.length) * 100)
      }));

    res.json({
      metric,
      rankings,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: Get latest analysis for a company (reuses existing logic)
async function getLatestAnalysis(ticker) {
  try {
    // Search for cached analysis or return mock data for demo
    for (const [key, value] of analysisCache) {
      if (key.startsWith(ticker + ':')) {
        return value.result;
      }
    }
    return null;
  } catch (err) {
    console.error(`Error fetching analysis for ${ticker}:`, err);
    return null;
  }
}

// ── TREND TRACKING ENDPOINTS (Phase 5, Task 8) ──────────────────────────────

// GET /api/trends/history - Get metric history over time
app.get('/api/trends/history', authMiddleware, async (req, res) => {
  try {
    const { ticker, metric, periods = 8 } = req.query;
    if (!ticker || !metric) {
      return res.status(400).json({ error: 'ticker and metric required' });
    }

    const history = await readJSON(METRICS_HISTORY_FILE).catch(() => []);
    const tickerHistory = history
      .filter(h => h.ticker === ticker.toUpperCase() && h[metric] !== undefined)
      .sort((a, b) => new Date(a.filingDate) - new Date(b.filingDate))
      .slice(-parseInt(periods));

    if (tickerHistory.length === 0) {
      return res.json({ ticker, metric, history: [], message: 'No history available' });
    }

    // Calculate overall trend
    const changeOverPeriod = tickerHistory.length > 1
      ? tickerHistory[tickerHistory.length - 1][metric] - tickerHistory[0][metric]
      : 0;

    const trend = changeOverPeriod > 0.5 ? 'improving' :
                  changeOverPeriod < -0.5 ? 'declining' : 'stable';

    res.json({
      ticker: ticker.toUpperCase(),
      metric,
      history: tickerHistory.map(h => ({
        date: h.filingDate,
        value: h[metric],
        formType: h.formType
      })),
      changeOverPeriod: parseFloat(changeOverPeriod.toFixed(2)),
      trend,
      dataPoints: tickerHistory.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/trends/status - Get current trend status for all metrics
app.get('/api/trends/status', authMiddleware, async (req, res) => {
  try {
    const { ticker } = req.query;
    if (!ticker) return res.status(400).json({ error: 'ticker required' });

    const trends = await readJSON(TRENDS_FILE).catch(() => []);
    const tickerTrends = trends.filter(t => t.ticker === ticker.toUpperCase());

    if (tickerTrends.length === 0) {
      return res.json({ ticker, summary: { improving: 0, declining: 0, stable: 0 }, trends: [] });
    }

    const summary = {
      improving: tickerTrends.filter(t => t.trendStatus === 'improving').length,
      declining: tickerTrends.filter(t => t.trendStatus === 'declining').length,
      stable: tickerTrends.filter(t => t.trendStatus === 'stable').length
    };

    res.json({
      ticker: ticker.toUpperCase(),
      summary,
      trends: tickerTrends.map(t => ({
        metric: t.metric,
        currentValue: t.currentValue,
        previousValue: t.previousValue,
        changePct: parseFloat(t.changePct.toFixed(2)),
        trendStatus: t.trendStatus
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────

async function startServer() {
  try {
    // Initialize file-based data directory
    await initDataDir();

    // Initialize database connection
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`\nFinRead server running → http://localhost:${PORT}`);
      console.log(`API key: ${process.env.ANTHROPIC_API_KEY ? '✓ configured' : '✗ NOT SET (add to .env)'}\n`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

// ── STATIC FILES (must come AFTER all API routes) ──────────────────────────────
app.use(express.static(__dirname));

// ── ERROR HANDLERS ────────────────────────────────────────────────────────────
// 404 handler - serve custom 404 page for undefined routes
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Global error handler - catch all unhandled errors
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).sendFile(path.join(__dirname, '500.html'));
});

// Start server locally, export app for Vercel serverless
if (require.main === module) {
  startServer();
} else {
  // For Vercel serverless, initialize database and export the app
  initializeDatabase().catch(err => console.error('Database init failed:', err));
}

module.exports = app;
