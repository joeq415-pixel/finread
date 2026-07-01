# Database Setup: Quick Reference

## ✅ What's Done

- ✅ Database client library installed (`@vercel/postgres`)
- ✅ Database helper file created (`db/client.js`)
- ✅ SQL schema created (`db/schema.sql`)
- ✅ Server.js updated with:
  - Database initialization on startup
  - Auth routes now use database (register/login)
  - Subscription tracking ready

---

## 🚀 Next Steps (for Deployment)

### Step 1: Create Vercel Postgres Database

1. Go to https://vercel.com/dashboard
2. Click **"Storage"** tab
3. Click **"Create Database"** → **"Postgres"**
4. Name: `finread-db`
5. Region: `us-east-1` (or closest to your users)
6. Click **"Create"**

**Result:** You'll get `POSTGRES_URL` connection string (Vercel auto-adds to env vars)

### Step 2: Initialize Database Schema

In your Vercel dashboard:

1. Go to your Postgres database
2. Click **"Query"** tab
3. Copy entire contents from `db/schema.sql`
4. Paste into the query editor
5. Click **"Execute"**

**Result:** All tables created with proper indexes

### Step 3: Push Code to GitHub

```bash
cd /Users/joesmacbook/Desktop/Claude\ Code

# Initialize git if not already done
git init

# Add all files
git add .

# Commit
git commit -m "Add database integration for Vercel Postgres

- Database client with Vercel Postgres
- Auth routes now use database instead of file storage
- Subscription tracking ready for Stripe
- Q&A audit logging for security

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>"

# Add GitHub remote (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/finread.git
git branch -M main
git push -u origin main
```

### Step 4: Deploy to Vercel

1. Go to https://vercel.com/dashboard
2. Click **"Add New..."** → **"Project"**
3. Click **"Import Git Repository"**
4. Search for and select `finread`
5. Click **"Import"**

**Vercel will:**
- Auto-detect Node.js
- Auto-add `POSTGRES_URL` env var
- Set up CI/CD

### Step 5: Add Environment Variables

In Vercel dashboard:
1. Go to your project
2. **Settings** → **Environment Variables**
3. Add these from your `.env`:

```
ANTHROPIC_API_KEY=sk_...
JWT_SECRET=<your-secret-key>
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_PRICE_ID_PRO=price_...
STRIPE_WEBHOOK_SECRET=whsec_...
FRONTEND_URL=https://finread.app
NODE_ENV=production
```

**Note:** `POSTGRES_URL` already added by Vercel

### Step 6: Deploy

Click **"Deploy"** in Vercel dashboard

**Deployment takes 2-3 minutes**

### Step 7: Connect Domain

1. Go to your project in Vercel
2. Click **"Settings"** → **"Domains"**
3. Add your domain: `finread.app`
4. Follow DNS instructions at your registrar
5. Vercel auto-generates free SSL certificate

---

## 📋 Testing

After deployment, test these endpoints:

```bash
# Register new user
curl -X POST https://finread.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123","name":"Test User"}'

# Response should have: token, user object

# Login
curl -X POST https://finread.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123"}'

# Check security headers
curl -I https://finread.app
# Should see: X-Frame-Options, X-Content-Type-Options, etc.
```

---

## 🐛 Troubleshooting

### "Database connection failed"
- ✅ Make sure Vercel Postgres database is created
- ✅ Make sure schema SQL was executed
- ✅ Check `POSTGRES_URL` env var is set in Vercel

### "Table does not exist"
- ✅ Re-run the schema SQL from `db/schema.sql`
- ✅ Check query executed successfully (no errors)

### "Email already registered"
- ✅ User already exists in database
- ✅ Use a different email or login instead

### "Invalid token"
- ✅ JWT_SECRET must be consistent across restarts
- ✅ Set `JWT_SECRET` in Vercel env vars (don't rely on random generation)

---

## 📊 Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| Database client | ✅ Ready | `db/client.js` |
| Auth routes | ✅ Updated | Using database |
| SQL schema | ✅ Ready | `db/schema.sql` |
| Server init | ✅ Updated | Calls `initializeDatabase()` |
| Code | ✅ Syntax OK | Verified with `node -c` |

---

## 🎯 Next: Local Testing (Optional)

Want to test database locally before deploying?

### Option A: Vercel Local
```bash
npm i -g vercel
vercel env pull  # Downloads env vars
vercel dev       # Runs with Vercel Postgres
```

### Option B: Skip Local Testing
Just deploy to Vercel directly - the database will work there

---

## 💡 After Deployment

You'll need to update these features to use the database:

1. **Watchlist** - Already ready in `db.addToWatchlist()`
2. **User preferences** - Can add to database
3. **Report history** - Can add new table
4. **Stripe subscriptions** - Already ready in `db.createSubscription()`

Each feature just needs to call the database methods instead of storing in files.

---

## 📞 Need Help?

Check these docs:
- [Vercel Postgres Docs](https://vercel.com/docs/storage/postgres)
- [Express + Database Guide](https://expressjs.com/en/guide/database-integration.html)
- [Node.js + PostgreSQL](https://node-postgres.com/)
