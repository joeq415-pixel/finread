const { sql } = require('@vercel/postgres');

// Check if database is available
async function initializeDatabase() {
  try {
    const result = await sql`SELECT 1`;
    console.log('✅ Database connected successfully');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    if (process.env.NODE_ENV === 'production') {
      console.error('CRITICAL: Database unavailable in production. Exiting.');
      process.exit(1);
    }
    return false;
  }
}

// User operations
const db = {
  // Create a new user
  async createUser(email, passwordHash, name) {
    try {
      console.log(`[DB] Creating user: ${email}`);
      const result = await sql`
        INSERT INTO users (email, password_hash, name)
        VALUES (${email}, ${passwordHash}, ${name})
        RETURNING id, email, name, created_at
      `;
      console.log(`[DB] User created successfully: ${result.rows[0].id}`);
      return result.rows[0];
    } catch (error) {
      console.error(`[DB] Error creating user: ${error.message}`);
      if (error.message.includes('duplicate key')) {
        throw new Error('User already exists');
      }
      throw error;
    }
  },

  // Get user by email
  async getUserByEmail(email) {
    const result = await sql`
      SELECT id, email, password_hash, name, created_at FROM users WHERE email = ${email}
    `;
    return result.rows[0];
  },

  // Get user by ID
  async getUserById(id) {
    const result = await sql`
      SELECT id, email, name, created_at FROM users WHERE id = ${id}
    `;
    return result.rows[0];
  },

  // Update user profile
  async updateUser(id, name) {
    const result = await sql`
      UPDATE users
      SET name = ${name}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ${id}
      RETURNING id, email, name
    `;
    return result.rows[0];
  },

  // Subscription operations
  async createSubscription(userId, stripeCustomerId, planType = 'free') {
    try {
      const result = await sql`
        INSERT INTO subscriptions (user_id, stripe_customer_id, plan_type, status)
        VALUES (${userId}, ${stripeCustomerId}, ${planType}, 'active')
        RETURNING *
      `;
      return result.rows[0];
    } catch (error) {
      if (error.message.includes('duplicate key')) {
        throw new Error('Subscription already exists');
      }
      throw error;
    }
  },

  // Get subscription by user ID
  async getSubscriptionByUserId(userId) {
    const result = await sql`
      SELECT * FROM subscriptions WHERE user_id = ${userId}
    `;
    return result.rows[0];
  },

  // Get subscription by Stripe customer ID
  async getSubscriptionByStripeCustomerId(stripeCustomerId) {
    const result = await sql`
      SELECT * FROM subscriptions WHERE stripe_customer_id = ${stripeCustomerId}
    `;
    return result.rows[0];
  },

  // Update subscription (Stripe webhook)
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

  // Cancel subscription
  async cancelSubscription(userId, cancelAt) {
    const result = await sql`
      UPDATE subscriptions
      SET status = 'cancelled',
          cancel_at = ${cancelAt},
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = ${userId}
      RETURNING *
    `;
    return result.rows[0];
  },

  // Watchlist operations
  async addToWatchlist(userId, ticker, companyName) {
    try {
      await sql`
        INSERT INTO watchlist_items (user_id, ticker, company_name)
        VALUES (${userId}, ${ticker}, ${companyName})
        ON CONFLICT (user_id, ticker) DO NOTHING
      `;
      return true;
    } catch (error) {
      console.error('Error adding to watchlist:', error);
      throw error;
    }
  },

  // Get watchlist
  async getWatchlist(userId) {
    const result = await sql`
      SELECT id, user_id, ticker, company_name, added_at
      FROM watchlist_items
      WHERE user_id = ${userId}
      ORDER BY added_at DESC
    `;
    return result.rows;
  },

  // Remove from watchlist
  async removeFromWatchlist(userId, ticker) {
    await sql`
      DELETE FROM watchlist_items
      WHERE user_id = ${userId} AND ticker = ${ticker}
    `;
    return true;
  },

  // Check if item in watchlist
  async isInWatchlist(userId, ticker) {
    const result = await sql`
      SELECT id FROM watchlist_items
      WHERE user_id = ${userId} AND ticker = ${ticker}
    `;
    return result.rows.length > 0;
  },

  // Audit logging for Q&A
  async logQAQuestion(userId, ticker, question, isRejected = false, reason = null) {
    try {
      await sql`
        INSERT INTO qa_audit_log (user_id, ticker, question, is_rejected, rejection_reason)
        VALUES (${userId}, ${ticker}, ${question}, ${isRejected}, ${reason})
      `;
    } catch (error) {
      console.error('Error logging Q&A question:', error);
      // Don't throw - logging failure shouldn't break the app
    }
  },

  // Get Q&A audit log for user
  async getQAAuditLog(userId, limit = 50) {
    const result = await sql`
      SELECT * FROM qa_audit_log
      WHERE user_id = ${userId}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
    return result.rows;
  }
};

module.exports = { db, initializeDatabase };
