# FinRead Deployment Guide: Local → Vercel

Complete step-by-step guide to deploy your website to production with Vercel + Vercel Postgres.

---

## 📋 Pre-Deployment Checklist

- [ ] Domain registered (or plan to register)
- [ ] GitHub account created
- [ ] Vercel account created (free)
- [ ] Stripe account set up (production keys ready)
- [ ] Review `.gitignore` (secrets protected)
- [ ] Review `.env.example` (template for Vercel)

---

## PHASE 1: Set Up Database (Vercel Postgres)

### Step 1.1: Create Vercel Project
1. Go to https://vercel.com/dashboard
2. Click **"Add New..."** → **"Project"**
3. Skip GitHub connection for now (we'll do it after code changes)
4. Name it: `finread`

### Step 1.2: Add Vercel Postgres
1. In your Vercel dashboard, go to **Storage** tab
2. Click **"Create Database"** → **"Postgres"**
3. Name it: `finread-db`
4. Region: Pick closest to your users (or us-east-1)
5. Click **"Create"**

**What you'll get:**
- Connection string (automatically added to env vars)
- Read-only credentials (optional)

### Step 1.3: Database Schema

Create `/db/schema.sql` with this structure:

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User subscriptions (Stripe integration)
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stripe_customer_id VARCHAR(255) UNIQUE,
  stripe_subscription_id VARCHAR(255) UNIQUE,
  plan_type VARCHAR(50), -- 'free', 'pro', 'enterprise'
  status VARCHAR(50), -- 'active', 'cancelled', 'past_due'
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  cancel_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Watchlist (saved filings)
CREATE TABLE watchlist_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ticker VARCHAR(10) NOT NULL,
  company_name VARCHAR(255),
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AI Q&A audit log
CREATE TABLE qa_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ticker VARCHAR(10),
  question TEXT,
  is_rejected BOOLEAN,
  rejection_reason VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe_customer_id ON subscriptions(stripe_customer_id);
CREATE INDEX idx_watchlist_user_id ON watchlist_items(user_id);
CREATE INDEX idx_qa_audit_user_id ON qa_audit_log(user_id);
```

### Step 1.4: Initialize Database

**Option A: Via Vercel Dashboard (Easiest)**
1. In Vercel dashboard, go to your Postgres database
2. Click **"Query"** tab
3. Paste the schema from above
4. Execute

**Option B: Via CLI (If you have psql installed)**
```bash
psql "your-connection-string-from-vercel" < db/schema.sql
```

---

## PHASE 2: Update Code for Production

### Step 2.1: Install Database Client

```bash
npm install @vercel/postgres bcryptjs jwt-decode
```

### Step 2.2: Create Database Helper (`db/client.js`)

Create a new file `/db/client.js`:

```javascript
const { sql } = require('@vercel/postgres');

// Check if database is available
async function initializeDatabase() {
  try {
    const result = await sql`SELECT 1`;
    console.log('✅ Database connected');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
}

// User operations
const db = {
  async createUser(email, passwordHash, name) {
    const result = await sql`
      INSERT INTO users (email, password_hash, name)
      VALUES (${email}, ${passwordHash}, ${name})
      RETURNING id, email, name
    `;
    return result.rows[0];
  },

  async getUserByEmail(email) {
    const result = await sql`
      SELECT id, email, password_hash, name FROM users WHERE email = ${email}
    `;
    return result.rows[0];
  },

  async getUserById(id) {
    const result = await sql`
      SELECT id, email, name FROM users WHERE id = ${id}
    `;
    return result.rows[0];
  },

  // Subscription operations
  async createSubscription(userId, stripeCustomerId, planType) {
    const result = await sql`
      INSERT INTO subscriptions (user_id, stripe_customer_id, plan_type, status)
      VALUES (${userId}, ${stripeCustomerId}, ${planType}, 'active')
      RETURNING *
    `;
    return result.rows[0];
  },

  async getSubscriptionByUserId(userId) {
    const result = await sql`
      SELECT * FROM subscriptions WHERE user_id = ${userId}
    `;
    return result.rows[0];
  },

  async updateSubscription(userId, updates) {
    const { stripe_subscription_id, status, current_period_end } = updates;
    const result = await sql`
      UPDATE subscriptions 
      SET stripe_subscription_id = ${stripe_subscription_id},
          status = ${status},
          current_period_end = ${current_period_end},
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = ${userId}
      RETURNING *
    `;
    return result.rows[0];
  },

  // Watchlist operations
  async addToWatchlist(userId, ticker, companyName) {
    await sql`
      INSERT INTO watchlist_items (user_id, ticker, company_name)
      VALUES (${userId}, ${ticker}, ${companyName})
      ON CONFLICT DO NOTHING
    `;
  },

  async getWatchlist(userId) {
    const result = await sql`
      SELECT * FROM watchlist_items WHERE user_id = ${userId} ORDER BY added_at DESC
    `;
    return result.rows;
  },

  async removeFromWatchlist(userId, ticker) {
    await sql`
      DELETE FROM watchlist_items WHERE user_id = ${userId} AND ticker = ${ticker}
    `;
  },

  // Audit logging
  async logQAQuestion(userId, ticker, question, isRejected, reason) {
    await sql`
      INSERT INTO qa_audit_log (user_id, ticker, question, is_rejected, rejection_reason)
      VALUES (${userId}, ${ticker}, ${question}, ${isRejected}, ${reason})
    `;
  }
};

module.exports = { db, initializeDatabase };
```

### Step 2.3: Update server.js to Use Database

Add at the top of `server.js` (after requires):

```javascript
const { db, initializeDatabase } = require('./db/client');

// Initialize database on startup
initializeDatabase().then(success => {
  if (!success && process.env.NODE_ENV === 'production') {
    console.error('CRITICAL: Database unavailable in production');
    process.exit(1);
  }
});
```

### Step 2.4: Update Auth Routes

Replace your current auth endpoints with database-backed versions:

```javascript
// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if user exists
    const existingUser = await db.getUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user in database
    const user = await db.createUser(email, passwordHash, name || email.split('@')[0]);

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token, user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get user from database
    const user = await db.getUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});
```

### Step 2.5: Update Stripe Webhook

```javascript
// POST /api/billing/webhook
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);

    switch (event.type) {
      case 'customer.subscription.updated':
        const subscription = event.data.object;
        // Find user by Stripe customer ID and update subscription
        const userId = await getUserIdByStripeCustomerId(subscription.customer);
        if (userId) {
          await db.updateSubscription(userId, {
            stripe_subscription_id: subscription.id,
            status: subscription.status,
            current_period_end: new Date(subscription.current_period_end * 1000)
          });
        }
        break;

      case 'customer.subscription.deleted':
        // Handle cancellation
        break;
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(400).send(`Webhook error: ${error.message}`);
  }
});
```

---

## PHASE 3: GitHub Setup

### Step 3.1: Initialize Git Repository

```bash
cd /Users/joesmacbook/Desktop/Claude\ Code
git init
git add .
git commit -m "Initial commit: FinRead financial analysis platform

- Core XBRL/SEC filing analysis with Claude AI
- PDF export functionality with modal-specific exports
- AI chatbot with topic validation and prompt injection detection
- Stripe billing integration
- Comprehensive security headers and rate limiting
- User authentication with JWT
- Vercel Postgres database schema

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"
```

### Step 3.2: Push to GitHub

1. Go to https://github.com/new
2. Create repository: `finread`
3. Do NOT initialize with README (we have one)
4. Run:

```bash
git remote add origin https://github.com/YOUR_USERNAME/finread.git
git branch -M main
git push -u origin main
```

---

## PHASE 4: Deploy to Vercel

### Step 4.1: Connect to Vercel

1. Go to https://vercel.com/dashboard
2. Click **"Add New..."** → **"Project"**
3. Click **"Import Git Repository"**
4. Search for `finread`
5. Click **"Import"**

### Step 4.2: Configure Environment Variables

In Vercel dashboard, go to **Settings** → **Environment Variables**

Add all from your `.env.example`:

```
ANTHROPIC_API_KEY=sk_...
JWT_SECRET=<your-jwt-secret>
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_PRICE_ID_PRO=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
FRONTEND_URL=https://finread.app
NODE_ENV=production
```

**Note:** `POSTGRES_URL` will be auto-added by Vercel when you linked the database.

### Step 4.3: Configure Build Settings

In Vercel:
1. **Framework Preset**: Node.js
2. **Build Command**: `npm run build` (or leave empty if no build needed)
3. **Output Directory**: (leave empty)
4. **Install Command**: `npm install`
5. Click **"Deploy"**

---

## PHASE 5: Domain Setup

### Step 5.1: Register Domain

1. Register at Namecheap, GoDaddy, or Cloudflare
   - Domain: `finread.app` (or your choice)
   - Cost: ~$10-15/year

### Step 5.2: Connect to Vercel

1. In Vercel dashboard, go to your project
2. Click **"Settings"** → **"Domains"**
3. Add your domain: `finread.app`
4. Follow instructions to update nameservers at your registrar
   - Or add DNS records (CNAME) pointing to Vercel
5. Vercel auto-generates free SSL certificate (HTTPS)

---

## PHASE 6: Post-Deployment Testing

### ✅ Test Checklist

- [ ] Website loads at `https://finread.app`
- [ ] Authentication (register/login) works
- [ ] Stripe payment flow works (test mode first)
- [ ] Filing analysis works
- [ ] PDF export works
- [ ] AI Q&A works (topic validation active)
- [ ] Security headers present (`https://securityheaders.com`)
- [ ] Database queries work
- [ ] Watchlist saves to database
- [ ] Rate limiting works
- [ ] CORS allows only your domain

### Test Commands

```bash
# Check security headers
curl -I https://finread.app

# Check database connection
curl https://finread.app/api/health

# Test authentication
curl -X POST https://finread.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test"}'
```

---

## 🚨 Common Issues & Solutions

### Issue: "Database connection failed"
- **Cause**: `POSTGRES_URL` env var not set
- **Fix**: Restart deployment after linking Postgres database

### Issue: "CORS error"
- **Cause**: Frontend domain not in allowedOrigins
- **Fix**: Update CORS whitelist in `server.js` and redeploy

### Issue: "Stripe webhook not firing"
- **Cause**: Webhook secret not set
- **Fix**: Update `STRIPE_WEBHOOK_SECRET` in Vercel env vars

### Issue: "JWT token invalid"
- **Cause**: Different JWT_SECRET on each deployment
- **Fix**: Set `JWT_SECRET` env var in Vercel (don't use random generation)

### Issue: "Static files not serving"
- **Cause**: `finread.html` not in public folder
- **Fix**: Create `/public` folder, move `finread.html` there, update Express:
  ```javascript
  app.use(express.static('public'));
  ```

---

## 📊 Monitoring & Maintenance

### Set Up Error Tracking

1. **Vercel Analytics** (built-in)
   - Dashboard shows errors automatically

2. **Optional: Sentry** (error tracking)
   ```bash
   npm install @sentry/node
   ```
   Add to top of server.js:
   ```javascript
   const Sentry = require('@sentry/node');
   Sentry.init({ dsn: process.env.SENTRY_DSN });
   app.use(Sentry.Handlers.errorHandler());
   ```

### Regular Checks

- [ ] Weekly: Check Vercel logs for errors
- [ ] Monthly: Review security audit logs
- [ ] Monthly: Check rate limit hits
- [ ] Quarterly: Update dependencies (`npm audit fix`)
- [ ] Quarterly: Test Stripe webhook flow

---

## 💰 Estimated Costs

| Service | Cost | Notes |
|---------|------|-------|
| Vercel Hosting | Free - $20/mo | Free tier good for start |
| Vercel Postgres | $15/mo | Includes daily backups |
| Domain | $10-15/yr | One-time annually |
| Anthropic API | $0.003-0.1/req | Pay-per-use, ~$100-500/mo depending on usage |
| Stripe | 2.9% + $0.30 per transaction | Only on successful payments |
| **Total** | **~$50-100/mo** | Scales with usage |

---

## 🎉 You're Live!

Once deployed:
1. ✅ Domain is live: `https://finread.app`
2. ✅ Database persists user data
3. ✅ Stripe handles payments securely
4. ✅ SSL/HTTPS everywhere
5. ✅ Auto-scaling handles traffic spikes
6. ✅ Auto-backups protect data

Next steps:
- Monitor Vercel dashboard daily first week
- Collect user feedback
- Plan feature updates
- Consider marketing

---

## 📞 Support

- **Vercel Docs**: https://vercel.com/docs
- **Postgres Docs**: https://www.postgresql.org/docs
- **Stripe Docs**: https://stripe.com/docs
- **Express Docs**: https://expressjs.com
