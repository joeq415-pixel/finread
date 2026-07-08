# Stripe Payment Setup Guide for FinRead

Complete guide to set up Stripe payment processing for the Pro subscription tier.

## Prerequisites

- Stripe account (create at https://stripe.com if you don't have one)
- Node.js running locally for testing
- `.env` file in your project root

## Step 1: Create Stripe Account

1. Go to https://stripe.com
2. Click "Sign up" and create an account
3. Verify your email
4. Complete your business information
5. Go to Dashboard > Settings > Business Settings to configure your business details

## Step 2: Get Your Stripe API Keys

1. In Stripe Dashboard, click "Developers" (left sidebar)
2. Click "API keys" tab
3. You'll see two keys:
   - **Publishable Key** (starts with `pk_`)
   - **Secret Key** (starts with `sk_`)

### Test vs Live Keys

- **Test Mode**: Use `pk_test_...` and `sk_test_...` for development
- **Live Mode**: Use `pk_live_...` and `sk_live_...` for production

**Important**: Never share your Secret Key! It has full access to your Stripe account.

## Step 3: Create Your Pro Plan/Price

1. Go to Stripe Dashboard > Product Catalog
2. Click "+ Add product"
3. Fill in product details:
   - **Name**: FinRead Pro
   - **Description**: Unlimited financial report analysis with advanced features
   - **Type**: Standard

4. Click "Add pricing"
5. Set pricing:
   - **Recurring** (subscription)
   - **Billing period**: Monthly (for now)
   - **Price**: $99.99/month (or your desired price)
   - **Billing cycle**: Monthly

6. Copy the **Price ID** (looks like `price_1K2J3L4M5N6O7P8Q`)
   - You'll need this in Step 4

## Step 4: Set Environment Variables

Add these to your `.env` file:

```bash
# Stripe Keys (from Step 2)
STRIPE_SECRET_KEY=sk_test_YOUR_ACTUAL_SECRET_KEY_HERE
STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_ACTUAL_PUBLISHABLE_KEY_HERE

# Stripe Configuration (from Step 3)
STRIPE_PRICE_ID_PRO=price_YOUR_ACTUAL_PRICE_ID_HERE

# Stripe Webhook Secret (from Step 5)
STRIPE_WEBHOOK_SECRET=whsec_YOUR_WEBHOOK_SIGNING_SECRET_HERE
```

**⚠️ Important**: Never commit `.env` to git. It contains secrets!

## Step 5: Set Up Webhook for Payment Confirmations

Webhooks allow Stripe to notify your server when payments complete.

### Local Testing with Stripe CLI

1. Download Stripe CLI: https://stripe.com/docs/stripe-cli
2. Install it on your machine
3. Authenticate with Stripe:
   ```bash
   stripe login
   ```
4. Forward Stripe events to your local server:
   ```bash
   stripe listen --forward-to localhost:3000/api/billing/webhook
   ```
5. This will output your **Webhook Signing Secret** (starts with `whsec_`)
6. Copy this secret to your `.env` file as `STRIPE_WEBHOOK_SECRET`

### Production Webhook Setup

For production, you need to set up the webhook in Stripe Dashboard:

1. Go to Stripe Dashboard > Developers > Webhooks
2. Click "Add endpoint"
3. Enter endpoint URL: `https://finread.io/api/billing/webhook` (replace with your domain)
4. Select events to listen for:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
5. Click "Add endpoint"
6. Copy the **Signing Secret** (whsec_...)
7. Add it to Railway environment variables (see Step 8)

## Step 6: Update Frontend Payment Button

The signup page needs a button to redirect to Stripe checkout.

In `finread.html`, the upgrade button should call:

```javascript
// Create checkout session
async function goToCheckout() {
  const token = localStorage.getItem('fr_token');
  const response = await fetch('/api/billing/checkout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  const { url } = await response.json();
  window.location.href = url; // Redirect to Stripe Checkout
}
```

## Step 7: Test Stripe Integration Locally

### Test Credit Card Numbers

Use these card numbers for testing (in test mode only):

- **Successful payment**: `4242 4242 4242 4242`
- **Failed payment**: `4000 0000 0000 0002`
- **Authentication required**: `4000 0025 0000 3155`

Expiry: Any future date
CVC: Any 3 digits

### Test Payment Flow

1. Start your server: `npm start`
2. In another terminal, start Stripe CLI: `stripe listen --forward-to localhost:3000/api/billing/webhook`
3. Navigate to signup page
4. Click "Upgrade to Pro"
5. You'll be redirected to Stripe Checkout
6. Use test card `4242 4242 4242 4242`
7. Fill in test details:
   - Email: your@email.com
   - Name: Test User
   - Address: Any valid address
8. Click "Subscribe"
9. You should see success confirmation
10. Check your database - user tier should be updated to "pro"

## Step 8: Deploy to Railway

### Add Environment Variables to Railway

1. Go to Railway Dashboard
2. Select your FinRead project
3. Click "Variables"
4. Add these variables:
   ```
   STRIPE_SECRET_KEY=sk_live_YOUR_LIVE_SECRET_KEY
   STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_LIVE_PUBLISHABLE_KEY
   STRIPE_PRICE_ID_PRO=price_YOUR_PRICE_ID
   STRIPE_WEBHOOK_SECRET=whsec_YOUR_WEBHOOK_SECRET
   ```

### Set Up Production Webhook

1. In Stripe Dashboard, create webhook for production domain
2. Endpoint: `https://finread.io/api/billing/webhook`
3. Add webhook secret to Railway variables

## Step 9: Update Pricing Page

1. Update the pricing display in `finread.html` with actual Stripe pricing
2. Replace "TBD" with actual monthly and yearly prices
3. Update the "Upgrade to Pro" button

## Step 10: Monitor Payments

### View Payments in Stripe Dashboard

1. Go to Stripe Dashboard > Payments
2. You'll see all successful transactions
3. Click on a payment to see details (customer, amount, status)

### View Subscriptions

1. Go to Stripe Dashboard > Billing > Subscriptions
2. See all active and past subscriptions
3. Monitor churn and cancellations

### Handle Refunds (if needed)

1. Go to Stripe Dashboard > Payments
2. Click on the payment you want to refund
3. Click "Refund" button
4. Select reason and amount
5. Confirm refund

## Common Issues & Troubleshooting

### "STRIPE_SECRET_KEY not set" error

**Problem**: Server won't start without Stripe key
**Solution**: Add `STRIPE_SECRET_KEY=sk_test_placeholder` to `.env` temporarily

### Webhook not receiving events

**Problem**: Payments succeed but subscription not activated
**Checks**:
- Verify webhook signing secret in `.env`
- Check Stripe CLI is running
- Check server logs for webhook errors
- Verify webhook events in Stripe Dashboard > Developers > Webhooks > Events

### Customer not found error

**Problem**: "No such customer" error on billing portal
**Cause**: User tried to access portal before any Stripe interaction
**Solution**: Create checkout session first to create customer

### Different amounts than expected

**Problem**: Payment amount differs from displayed price
**Cause**: Stripe prices are in cents, display is in dollars
**Solution**: Check STRIPE_PRICE_ID_PRO and verify price in Stripe Dashboard

## Security Checklist

- [ ] Never commit `.env` file to git
- [ ] Use `sk_live_` keys in production, not test keys
- [ ] Enable 3D Secure for card payments
- [ ] Set up PCI compliance (Stripe handles most of it)
- [ ] Monitor for suspicious transactions
- [ ] Regularly rotate webhook secrets
- [ ] Use HTTPS in production (Railway provides this)
- [ ] Validate webhook signatures server-side (already done in code)

## Next Steps

After setup is complete:

1. Test the full payment flow locally
2. Deploy to Railway with live keys
3. Test with real payment method in production
4. Monitor first transactions
5. Set up email confirmations for successful payments
6. Create customer support documentation for refunds/cancellations
7. Monitor churn rate and consider retention strategies

## Helpful Resources

- Stripe Docs: https://stripe.com/docs
- Pricing Page Setup: https://stripe.com/docs/billing/how-to-build-pricing-page
- Webhook Events: https://stripe.com/docs/api/events
- Testing: https://stripe.com/docs/testing

## Support

If you encounter issues:
1. Check Stripe Status: https://status.stripe.com/
2. Review Stripe Documentation
3. Check server logs for API errors
4. Verify webhook events in Stripe Dashboard
5. Contact Stripe Support: https://stripe.com/docs/support

