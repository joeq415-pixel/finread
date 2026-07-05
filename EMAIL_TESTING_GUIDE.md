# Email Verification & Password Reset Testing Guide

Before going live, thoroughly test all email-related functionality to ensure users can properly register and recover their accounts.

## Prerequisites

- Resend API key configured in environment variables (`.env` file)
- Test email address that can receive emails
- Access to both development and production environments

## Email Configuration

**Current Setup:**
- Email Service: Resend
- Test Email: `onboarding@resend.dev` (test mode - limited delivery)
- Production Email: Your verified domain (when available)

### Current Limitations (Development)

⚠️ **Important**: In test mode, Resend can only send to your account owner email address (`joeq415@gmail.com`). For production testing, you'll need to verify a domain.

## Test Checklist

### 1. Sign Up & Email Verification

**Test Case 1.1: Valid Sign Up**
- [ ] Navigate to home page, click "Sign Up"
- [ ] Enter test email: `joeq415@gmail.com`
- [ ] Enter password: `TestPassword123`
- [ ] Submit form
- [ ] Verify success message appears
- [ ] Check email inbox for verification email
- [ ] Verify email contains:
  - [ ] "Verify Email" subject
  - [ ] Account name
  - [ ] Verification link with token
  - [ ] Professional formatting
- [ ] Click verification link in email
- [ ] Verify success page shows "Email Verified!"
- [ ] Confirm account is now active in database

**Test Case 1.2: Invalid Email Format**
- [ ] Try signing up with invalid email (e.g., "notanemail")
- [ ] Verify error message appears
- [ ] Verify no email is sent

**Test Case 1.3: Duplicate Email**
- [ ] Try signing up with same email twice
- [ ] Verify error message: "Email already registered"
- [ ] Verify only one account exists

**Test Case 1.4: Weak Password**
- [ ] Try signing up with password < 8 characters
- [ ] Verify error message appears

### 2. Password Reset Flow

**Test Case 2.1: Forgot Password - Valid Email**
- [ ] Click "Forgot password?" on login page
- [ ] Enter registered email: `joeq415@gmail.com`
- [ ] Click "Send Reset Link"
- [ ] Verify success message appears
- [ ] Check email inbox for password reset email
- [ ] Verify email contains:
  - [ ] "Reset Your Password" subject
  - [ ] Reset link with token
  - [ ] Expiration time (1 hour)
  - [ ] Professional formatting

**Test Case 2.2: Reset Password - Valid Link**
- [ ] Click reset link from email
- [ ] Verify reset password page loads
- [ ] Enter new password: `NewPassword123`
- [ ] Confirm password: `NewPassword123`
- [ ] Click "Reset Password"
- [ ] Verify success message: "Password reset successfully"
- [ ] Wait 2 seconds for redirect to login
- [ ] Verify redirected to home page
- [ ] Login with new password
- [ ] Verify login successful

**Test Case 2.3: Reset Password - Mismatched Passwords**
- [ ] Click reset link from email
- [ ] Enter password: `NewPassword123`
- [ ] Confirm password: `DifferentPassword123`
- [ ] Click "Reset Password"
- [ ] Verify error: "Passwords do not match"

**Test Case 2.4: Reset Password - Weak Password**
- [ ] Click reset link from email
- [ ] Enter password: `short`
- [ ] Confirm password: `short`
- [ ] Click "Reset Password"
- [ ] Verify error: "Password must be at least 8 characters"

**Test Case 2.5: Expired Token**
- [ ] Manually craft URL with expired token: `/reset-password?token=expired-token`
- [ ] Try to reset password
- [ ] Verify error: "Invalid reset link"

**Test Case 2.6: Forgot Password - Non-existent Email**
- [ ] Enter non-registered email
- [ ] Verify success message still appears (don't leak if email exists)
- [ ] Verify no email is sent

### 3. Email Delivery Quality Checks

For each email, verify:

**Content Quality**
- [ ] Subject line is clear and professional
- [ ] Email body is readable
- [ ] Links are clickable
- [ ] No broken formatting
- [ ] Logo/branding is present
- [ ] Contact information is included

**Deliverability**
- [ ] Email arrives within 2 minutes
- [ ] Not marked as spam
- [ ] All links in email work correctly
- [ ] Tokens in URLs are valid and unexpired

**Token Security**
- [ ] Tokens are long, random strings
- [ ] Tokens work only once
- [ ] Expired tokens are rejected
- [ ] Invalid tokens are rejected
- [ ] Tokens are not visible in plain text anywhere

### 4. Light/Dark Mode Email Display

**Test Case 4.1: Email Client Rendering**
- [ ] Check email in light theme email client
- [ ] Check email in dark theme email client
- [ ] Verify text is readable in both modes
- [ ] Verify buttons are visible in both modes

### 5. Production Readiness

**Pre-Launch Verification**

- [ ] Resend API key is configured in production environment
- [ ] Domain is verified with Resend (if not using test email)
- [ ] From email address is set correctly in production
- [ ] Email templates match brand guidelines
- [ ] Rate limiting is in place to prevent spam
- [ ] Error logging is enabled for failed email sends
- [ ] Unsubscribe links are included (if applicable)
- [ ] Privacy policy link is in footer of all emails

### 6. Monitoring & Alerts

Set up alerts for:
- [ ] Failed email sends
- [ ] High bounce rates
- [ ] Spam complaints
- [ ] High error rates on email endpoints

## Quick Test Script

```bash
# Test health check endpoint
curl http://localhost:3000/health

# Expected response:
# {"status":"ok","timestamp":"2024-07-05T...", "uptime":...}
```

## Troubleshooting

### Email Not Received
1. Check spam/junk folder
2. Verify email address is correct
3. Check Resend API key is set: `echo $RESEND_API_KEY`
4. Check server logs for errors: `tail server.log`
5. In test mode, verify using account owner email

### Token Expired
- Email verification tokens: 24 hours
- Password reset tokens: 1 hour
- Check token generation timestamp in database

### Email Formatting Issues
- Check email client support for CSS
- Verify image links are absolute URLs
- Test in multiple email clients (Gmail, Outlook, Apple Mail)

## Sign-Off

Once all tests pass, record:
- [ ] Date tested: ___________
- [ ] Tester name: ___________
- [ ] Test environment: [ ] Dev [ ] Staging [ ] Production
- [ ] All tests passed: [ ] Yes [ ] No
- [ ] Issues found: ___________
- [ ] Ready for launch: [ ] Yes [ ] No

