-- FinRead Database Schema for Vercel Postgres

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User subscriptions (Stripe integration)
CREATE TABLE IF NOT EXISTS subscriptions (
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
CREATE TABLE IF NOT EXISTS watchlist_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ticker VARCHAR(10) NOT NULL,
  company_name VARCHAR(255),
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, ticker)
);

-- AI Q&A audit log
CREATE TABLE IF NOT EXISTS qa_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ticker VARCHAR(10),
  question TEXT,
  is_rejected BOOLEAN DEFAULT FALSE,
  rejection_reason VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer_id ON subscriptions(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_watchlist_user_id ON watchlist_items(user_id);
CREATE INDEX IF NOT EXISTS idx_qa_audit_user_id ON qa_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_qa_audit_created_at ON qa_audit_log(created_at);
