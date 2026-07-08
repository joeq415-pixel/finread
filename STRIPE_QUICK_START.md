# Stripe Quick Start Checklist

## 5-Minute Setup

### 1. Create Stripe Account
- [ ] Go to https://stripe.com
- [ ] Sign up for account
- [ ] Verify email and complete setup

### 2. Get API Keys
- [ ] Go to Developers > API Keys
- [ ] Copy **Secret Key** (sk_test_...)
- [ ] Copy **Publishable Key** (pk_test_...)

### 3. Create Pro Product & Price
- [ ] Go to Product Catalog > Add Product
- [ ] Name: "FinRead Pro"
- [ ] Price: $99.99/month (monthly billing)
- [ ] Copy **Price ID** (price_...)

### 4. Add to .env File
```bash
STRIPE_SECRET_KEY=sk_test_YOUR_KEY
STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_KEY
STRIPE_PRICE_ID_PRO=price_YOUR_ID
```

### 5. Test Locally
- [ ] Start server: `npm start`
- [ ] Use test card: `4242 4242 4242 4242`
- [ ] Test checkout flow
- [ ] Verify subscription created in database

### 6. Deploy to Railway
- [ ] Add Stripe keys to Railway environment variables
- [ ] Use live keys (sk_live_... and pk_live_...)
- [ ] Set up webhook in Stripe Dashboard
- [ ] Test live payment

## Test Card Numbers

| Card | Number | Use |
|------|--------|-----|
| Visa (Success) | 4242 4242 4242 4242 | Successful payments |
| Visa (Decline) | 4000 0000 0000 0002 | Test decline scenario |
| 3D Secure | 4000 0025 0000 3155 | Authentication required |

**Expiry**: Any future date  
**CVC**: Any 3 digits

## Environment Variables Reference

```bash
# Test Keys
STRIPE_SECRET_KEY=sk_test_51K2J3L4M5N6O...
STRIPE_PUBLISHABLE_KEY=pk_test_51K2J3L4M5N6O...

# Live Keys (Production)
STRIPE_SECRET_KEY=sk_live_51K2J3L4M5N6O...
STRIPE_PUBLISHABLE_KEY=pk_live_51K2J3L4M5N6O...

# Price ID
STRIPE_PRICE_ID_PRO=price_1K2J3L4M5N6O7P8Q

# Webhook Secret (from Stripe CLI or Dashboard)
STRIPE_WEBHOOK_SECRET=whsec_1K2J3L4M5N6O...
```

## API Endpoints Already Available

Your server already has these Stripe endpoints:

```bash
# Create checkout session (user clicks upgrade)
POST /api/billing/checkout
Response: { url: "https://checkout.stripe.com/..." }

# Access billing portal (manage subscription)
POST /api/billing/portal
Response: { url: "https://billing.stripe.com/..." }

# Webhook for payment events
POST /api/billing/webhook
Handles: checkout.session.completed, subscription updates/cancellations
```

## Testing Payment Flow

```
User clicks "Upgrade to Pro"
  ↓
POST /api/billing/checkout
  ↓
Redirected to Stripe Checkout
  ↓
Enter card: 4242 4242 4242 4242
  ↓
Stripe processes payment
  ↓
Webhook event: checkout.session.completed
  ↓
Server updates user tier to "pro"
  ↓
User redirected to success page
```

## Key Points

✅ **Already configured in server.js**:
- Stripe client initialized
- Checkout endpoint (`/api/billing/checkout`)
- Billing portal endpoint (`/api/billing/portal`)
- Webhook handler for payment events
- Database fields for tracking subscription

⚠️ **Still needed**:
- [ ] Stripe account & API keys
- [ ] Price ID for Pro plan
- [ ] Add keys to `.env` file
- [ ] Set up webhook (for production)
- [ ] Update pricing display in UI
- [ ] Test full flow

## Where to Find Things in Stripe Dashboard

| Item | Location |
|------|----------|
| API Keys | Developers > API Keys |
| Products | Product Catalog |
| Prices | Product Catalog > [Product] > Pricing |
| Payments | Payments |
| Subscriptions | Billing > Subscriptions |
| Webhooks | Developers > Webhooks |
| Events | Developers > Events |
| Customers | Customers |
| Settings | Settings > Business Settings |

## Webhook Events to Monitor

The server listens for these Stripe events:

1. **checkout.session.completed**
   - When user completes checkout
   - Sets up subscription
   - Updates user tier to "pro"

2. **customer.subscription.updated**
   - When subscription changes (e.g., billing address update)
   - Ensures tier stays in sync

3. **customer.subscription.deleted**
   - When subscription is cancelled
   - Downgrades user back to "free" tier

## Support

- Stripe Docs: https://stripe.com/docs
- Test Mode Docs: https://stripe.com/docs/testing
- CLI Setup: https://stripe.com/docs/stripe-cli
- For full details, see **STRIPE_SETUP_GUIDE.md**

