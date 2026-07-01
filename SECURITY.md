# FinRead Security Guide

## Current Security Measures

### ✅ Implemented

#### 1. **Secrets Management** (server.js, lines 12-102)
- Environment variables for all sensitive keys (ANTHROPIC_API_KEY, JWT_SECRET, STRIPE keys)
- `.env` file protected from version control via `.gitignore`
- `.env.example` template for new deployments

#### 2. **Security Headers Middleware** (server.js)
- **X-Content-Type-Options: nosniff** — Prevents MIME type sniffing
- **X-Frame-Options: DENY** — Stops clickjacking attacks
- **X-XSS-Protection: 1; mode=block** — Enables XSS filter in older browsers
- **Strict-Transport-Security** — Forces HTTPS in production
- **Content-Security-Policy** — Restricts resource loading to same-origin
- **Referrer-Policy: strict-origin-when-cross-origin** — Limits referrer exposure
- **Permissions-Policy** — Disables dangerous APIs (geolocation, camera, microphone)

#### 3. **CORS Protection** (server.js, lines ~12-30)
- Whitelist of allowed origins (localhost, finread.app, FRONTEND_URL env var)
- Validates origin on every request before setting CORS headers
- Prevents unauthorized cross-origin access

#### 4. **Request Size Limits** (server.js, line ~35)
- Max 10MB payload size for JSON and form data
- Prevents denial-of-service via oversized uploads

#### 5. **Global Rate Limiting** (server.js, lines ~40-50)
- 1000 requests/minute per IP address
- Blocks brute force and DOS attacks

#### 6. **Input Sanitization** (server.js)
- Helper function: `global.sanitizeInput()` 
- Removes XSS-dangerous characters before storing/displaying

#### 7. **AI Chatbot Security** (server.js, finread.html)
- **Topic Validation (2-layer)**:
  - Client-side: Blocks off-topic questions in UX (research/recipes/jokes/sports)
  - Server-side: Second validation prevents prompt injection bypass
- **Rate Limiting per User**: 30 questions/hour per user ID
- **Prompt Injection Detection**: Regex patterns for common injection attacks
  - "ignore previous instructions"
  - "system prompt"
  - "pretend to be / act as"
  - "forget rules / don't follow rules"
  - etc.
- **Audit Logging**: All Q&A questions logged with timestamp, user ID, status, rejection reason
- **Default Rejection**: Off-topic questions rejected: "Please ask questions related to [Company] and its financial information."

#### 8. **JWT Authentication** (server.js)
- JWT tokens with 30-day expiration
- Random JWT_SECRET (cryptographic random bytes)
- Token verification on protected routes

#### 9. **API Endpoint Security** (server.js)
- All sensitive endpoints check authentication
- Input validation on query parameters and request bodies
- Logging of security events (failed auth, rate limit hits, injection attempts)

#### 10. **Code Theft Protection**
- ✅ `.gitignore` prevents secrets from being committed
- ✅ Environment variables keep API keys out of source code
- ✅ `.env.example` template included for safe sharing

---

## 🚨 Deployment Checklist

### Before going to production:

- [ ] **Set `NODE_ENV=production`** in production environment
  - Activates HSTS and additional security headers
  
- [ ] **Use strong JWT_SECRET**
  - Already generated: `crypto.randomBytes(32).toString('hex')`
  - Make sure it's 32+ characters
  
- [ ] **Use real Stripe keys** (not `sk_test_placeholder`)
  - Replace with production secret key
  
- [ ] **Update FRONTEND_URL** environment variable
  - Add your actual frontend domain to CORS whitelist
  
- [ ] **Enable HTTPS**
  - All communication must be encrypted
  - Use Let's Encrypt (free SSL certificates)
  
- [ ] **Use a production database**
  - Not SQLite or file-based
  - Use PostgreSQL or managed database service
  
- [ ] **Set up secrets management**
  - AWS Secrets Manager, Azure Key Vault, or similar
  - Never commit `.env.production`
  
- [ ] **Enable HTTPS-only cookies**
  - Add to JWT/session middleware: `secure: process.env.NODE_ENV === 'production'`
  
- [ ] **Set up monitoring/alerting**
  - Monitor rate limit logs for attacks
  - Alert on failed authentication attempts
  - Track AI abuse patterns

---

## 📋 Security Headers Testing

Test your security headers in production:

1. **Self-check**: Visit https://securityheaders.com and enter your domain
2. **Expected Grade**: Should be A+ (all major headers in place)
3. **What to look for**:
   - ✅ X-Content-Type-Options
   - ✅ X-Frame-Options
   - ✅ Strict-Transport-Security (production only)
   - ✅ Content-Security-Policy
   - ✅ Referrer-Policy

---

## 🔒 Optional Enhancements

### 1. **Add Helmet.js** (recommended)
```javascript
const helmet = require('helmet');
app.use(helmet());
```

### 2. **Add Express Validator** (for input validation)
```javascript
const { body, validationResult } = require('express-validator');
app.post('/api/qa', [
  body('question').trim().escape().isLength({ max: 1000 })
], (req, res) => { ... });
```

### 3. **Add Compression** (reduces payload size)
```javascript
const compression = require('compression');
app.use(compression());
```

### 4. **Add HTTPS Redirect**
```javascript
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});
```

### 5. **Database Query Sanitization**
- Use parameterized queries (avoid string concatenation)
- Already done if using an ORM like Sequelize or Prisma

---

## 📊 Security Event Logging

Your system logs:
- ✅ Failed authentication attempts
- ✅ Rate limit violations
- ✅ Prompt injection attempts
- ✅ Off-topic Q&A questions
- ✅ CORS violations

**Action**: Review logs regularly for suspicious patterns

---

## 🎯 Code Theft Prevention

### What's protected:
- ✅ `.env` secrets excluded from git
- ✅ API keys in environment variables only
- ✅ `node_modules/` excluded from version control
- ✅ Source code visible to client (normal, unavoidable)

### What's NOT protected:
- ❌ Client-side JavaScript (always visible in browser)
- ❌ HTML/CSS (sent to browser, visible to users)

**Note**: Client-side code theft is normal and unavoidable. All client-side code is downloadable by anyone visiting your site. This is why you:
1. Don't put secrets in client-side code ✅ (already doing this)
2. Keep server-side logic on the server ✅ (already doing this)
3. Use authentication on protected endpoints ✅ (already doing this)

---

## 🚀 Next Steps

1. ✅ **Created `.gitignore`** — Prevents secret commits
2. **Test in production**:
   - Deploy to staging/production
   - Run https://securityheaders.com check
   - Monitor logs for attacks
3. **Optional**: Implement Helmet.js and additional middleware
4. **Regular audits**: Review logs monthly for security events

---

## 📞 Security Contact

If you discover a security vulnerability:
1. Do NOT post it publicly
2. Create a private GitHub issue or email your security contact
3. Provide reproduction steps
4. Allow 30 days for fixes before public disclosure

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/nodejs-web-app-security/)
- [Express Security Guide](https://expressjs.com/en/advanced/best-practice-security.html)
- [Content Security Policy Reference](https://content-security-policy.com/)
