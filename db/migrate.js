require('dotenv').config();
const { sql } = require('@vercel/postgres');

async function runMigration() {
  try {
    console.log('🔄 Starting database migration...');

    // Create users table
    console.log('📝 Creating users table...');
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('✅ users table created');

    // Create subscriptions table
    console.log('📝 Creating subscriptions table...');
    await sql`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        stripe_customer_id VARCHAR(255) UNIQUE,
        stripe_subscription_id VARCHAR(255) UNIQUE,
        plan_type VARCHAR(50),
        status VARCHAR(50),
        current_period_start TIMESTAMP,
        current_period_end TIMESTAMP,
        cancel_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('✅ subscriptions table created');

    // Create watchlist_items table
    console.log('📝 Creating watchlist_items table...');
    await sql`
      CREATE TABLE IF NOT EXISTS watchlist_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ticker VARCHAR(10) NOT NULL,
        company_name VARCHAR(255),
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, ticker)
      )
    `;
    console.log('✅ watchlist_items table created');

    // Create qa_audit_log table
    console.log('📝 Creating qa_audit_log table...');
    await sql`
      CREATE TABLE IF NOT EXISTS qa_audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ticker VARCHAR(10),
        question TEXT,
        is_rejected BOOLEAN DEFAULT FALSE,
        rejection_reason VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('✅ qa_audit_log table created');

    // Create email_verification_tokens table
    console.log('📝 Creating email_verification_tokens table...');
    await sql`
      CREATE TABLE IF NOT EXISTS email_verification_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('✅ email_verification_tokens table created');

    // Create password_reset_tokens table
    console.log('📝 Creating password_reset_tokens table...');
    await sql`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('✅ password_reset_tokens table created');

    // Create indexes
    console.log('📝 Creating indexes...');
    await sql`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer_id ON subscriptions(stripe_customer_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_watchlist_user_id ON watchlist_items(user_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_qa_audit_user_id ON qa_audit_log(user_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_qa_audit_created_at ON qa_audit_log(created_at)`;
    console.log('✅ Indexes created');

    console.log('\n✅ Migration completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    console.error(error);
    process.exit(1);
  }
}

runMigration();
