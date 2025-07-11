// ✅ Load environment variables
require('dotenv').config();


// ✅ Core dependencies and modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const sgMail = require('@sendgrid/mail');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const crypto = require('crypto');
const Joi = require('joi');
const { body, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const apicache = require('apicache');
const cache = apicache.middleware;
const formatCurrency = require('./utils/formatCurrency');
const logger = require('./utils/logger');
const { notifyAdmin } = require('./utils/alerts');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const { csrfCookieName, options } = require('./config/csrf-config');
 

const app = express();

app.set('trust proxy', true);  // Trust Render.com proxies
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const isProduction = process.env.NODE_ENV === 'production';


// Generate CSP nonce per request
app.use((req, res, next) => {
  res.locals.cspNonce = Buffer.from(crypto.randomBytes(16)).toString('base64');
  next();
});

// Apply CSP headers using middleware wrapper
app.use((req, res, next) => {
  helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'",
        `'nonce-${res.locals.cspNonce}'`,
        "https://fonts.googleapis.com ",
        "https://cdnjs.cloudflare.com "
      ],
      scriptSrc: [
        "'self'",
        `'nonce-${res.locals.cspNonce}'`,
        "https://cdnjs.cloudflare.com "
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com ",
        "https://cdnjs.cloudflare.com "
      ],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "https://api.paystack.co "]
    }
  })(req, res, next);
});

// Add getSessionIdentifier to options
const finalOptions = {
  ...options,
  getSessionIdentifier: (req) => req.sessionID
};

// Apply after session middleware
app.use(session({ /* your session config */ }));




// ✅ CORS Configuration - Added per security recommendation
app.use(cors({ 
  origin: process.env.FRONTEND_URL || process.env.FRONTEND_BASE_URL,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.static(path.join(__dirname, 'public')));

// Static + body parsers
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

app.use(cookieParser());

// MISSING: Session middleware configuration
app.use(session({
  name: '__Host-hc-session',
  store: new pgSession({
    pool: pgPool,
    tableName: 'session',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || 'fallback-secret-for-dev',
  resave: false,
  saveUninitialized: false,
  cookie: {
    path: '/',
    secure: isProduction,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

const { doubleCsrfProtection } = doubleCsrf({
  ...options,
  getSessionIdentifier: (req) => req.sessionID
});

app.use(doubleCsrfProtection);

app.use((req, res, next) => {
  try {
    res.locals.csrfToken = req.csrfToken();
    res.cookie(csrfCookieName, res.locals.csrfToken, {
      httpOnly: false,
      sameSite: 'lax',
      secure: isProduction,
      path: '/',
      maxAge: 15 * 60 * 1000
    });
    next();
  } catch (err) {
    logger.error('CSRF token error:', err.message);
    next(err);
  }
});


// Serve static files from "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Generate CSP nonce for each request
app.use((req, res, next) => {
  // Generate a base64-encoded random value for CSP nonce
  const nonce = Buffer.from(crypto.randomBytes(16)).toString('base64');
  res.locals.cspNonce = nonce;
  next();
});


logger.info('NODE_ENV:', process.env.NODE_ENV);

function validateRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
}


const BCRYPT_COST = Math.min(
  Math.max(parseInt(process.env.BCRYPT_COST) || 8, 8),
  12
);
logger.info(`🔒 Using bcrypt cost factor: ${BCRYPT_COST}`);

// Add after bodyParser middleware:
app.use((req, res, next) => {
  if (req.params.id) {
    const id = parseInt(req.params.id);
    req.sanitizedId = isNaN(id) ? null : id;
  }
  next();
});

// Add after Joi require:
const metadataSchema = Joi.object({
  staffId: Joi.string().optional(),
  projectId: Joi.string().optional(),
  donorName: Joi.string().optional(),
  donationType: Joi.string().valid('one-time', 'recurring').optional()
});


// ✅ Database connection
const db = require('./db');
logger.info("🛠 Using DB Connection:", db.client.config.connection);
logger.info("🌍 Running in environment:", process.env.NODE_ENV);

// Critical environment validation
const requiredEnvVars = [
  'PAYSTACK_SECRET_KEY',
  'DATABASE_URL',
  'FRONTEND_URL',
  'SENDGRID_API_KEY'
];

const missingVars = requiredEnvVars.filter(env => !process.env[env]);
if (missingVars.length > 0) {
  throw new Error(`❌ Critical ENV variables missing: ${missingVars.join(', ')}`);
}


// ✅ Rate Limiters
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  message: 'Too many payment requests from this IP, please try again later'
});

const webhookLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100,
  message: 'Too many webhook requests'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many login attempts, please try again later'
});

// ✅ Paystack webhook verification
const verifyPaystackWebhook = (req, res, next) => {
  // Use raw body instead of JSON.stringify(req.body)
  const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                     .update(req.rawBody) // CHANGED THIS LINE
                     .digest('hex');
  
  if (hash === req.headers['x-paystack-signature']) {
    return next();
  }
  res.status(401).send('Unauthorized');
};

function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Add after escapeHtml function
function sanitizeHeader(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\r\n]/g, '');
}

// ✅ Secure Basic Auth Middleware
const requireAuth = (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Basic ')) {
    return res.status(401)
      .set('WWW-Authenticate', 'Basic realm="Dashboard"')
      .send('Authentication required.');
  }

  const base64Credentials = auth.split(' ')[1];

  let credentials;
  try {
    credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  } catch (e) {
    return res.status(400).send('Invalid authorization format.');
  }

  const [username, password] = credentials.split(':');

  if (!username || !password) {
    return res.status(400).send('Missing username or password.');
  }

  if (username === process.env.DASHBOARD_USER && password === process.env.DASHBOARD_PASS) {
    return next();
  }

  return res.status(401).send('Access denied.');
};

// ✅ Helper: Fetch name of staff or project
async function getDisplayName(type, id, db) {
  logger.info(`🔍 Looking up ${type} ID: ${id}`);
  const numericId = typeof id === 'string' ? parseInt(id) : id;
  if (typeof numericId !== 'number' || isNaN(numericId) || numericId <= 0) {
    logger.info(`❌ Invalid ID: ${id}`);
    return null;
  }
  try {
    const table = type === 'staff' ? 'staff' : 'projects';
    const result = await db(table).where('id', numericId).first();
    if (result) {
      logger.info(`✅ Found ${type}:`, result);
      return result.name;
    } else {
      const allRecords = await db(table).select('*');
      logger.info(`❌ No ${type} found with ID: ${numericId}`);
      logger.info(`📋 All ${type} records:`, allRecords);
      return null;
    }
  } catch (err) {
    logger.error(`❌ Database error:`, err);
    return null;
  }
}

// ✅ Custom Error Classes
class AppError extends Error {
  constructor(message, status) {
    super(message);
    this.name = this.constructor.name;
    this.status = status || 500;
    Error.captureStackTrace(this, this.constructor);
  }
}

class DatabaseError extends AppError {
  constructor(message) {
    super(message || 'Database operation failed', 500);
  }
}

class NotFoundError extends AppError {
  constructor(message) {
    super(message || 'Resource not found', 404);
  }
}

app.get('/csrf-test', doubleCsrfProtection, (req, res) => {
  res.send(`Your CSRF token is: ${res.locals.csrfToken}`);
});


// Health check endpoint (for Render and debugging)
app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

// ✅ Database initialization
async function initializeDatabase() {
  try {
    await db.migrate.latest();
    logger.info('📦 Migrations completed');
    const staff = await db('staff').select('*');
    logger.info('👥 Staff records:', staff);
  } catch (err) {
    logger.error('❌ Database initialization error:', err.message);
  }
}


app.get('/', (req, res, next) => {
  logger.debug('[ROUTE /] About to render donation-form EJS');
  res.render('donation-form', {
    cspNonce: res.locals.cspNonce,
    csrfToken: res.locals.csrfToken
  });
});


  app.get('/debug/donations', requireAuth, async (req, res, next) => {
    try {
      const all = await db('donations').select('*');
      res.json(all);
    } catch (err) {
      next(new DatabaseError('Failed to fetch debug donation data'));
    }
  });


// Payment initialization endpoint
app.post('/initialize-payment',
  paymentLimiter,
  async (req, res) => {
    logger.debug('[POST /initialize-payment] --- TOP OF ROUTE ---');
    logger.debug('[POST /initialize-payment] Request cookies:', req.cookies);
    logger.debug('[POST /initialize-payment] Session ID:', req.sessionID);
    logger.debug('[POST /initialize-payment] Session:', req.session);
    logger.debug('[POST /initialize-payment] X-CSRF-Token header:', req.headers['x-csrf-token']);
    logger.debug('[POST /initialize-payment] body._csrf:', req.body._csrf);
    try {
      const { email, amount, currency, metadata } = req.body;
      const amountInKobo = amount * 100;

      const paymentData = {
        email,
        amount: amountInKobo,
        currency,
        metadata,
        callback_url: `${process.env.FRONTEND_BASE_URL}/thank-you`
      };

      const response = await axios.post(
        'https://api.paystack.co/transaction/initialize',
        paymentData,
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      res.json({
        status: 'success',
        authorization_url: response.data.data.authorization_url,
        reference: response.data.data.reference
      });

    } catch (error) {
      logger.error(error.response?.data || error.message);
      // Always return JSON error for frontend
      if (error.response && error.response.data) {
        // Paystack or axios error with response
        return res.status(error.response.status || 500).json({
          status: 'error',
          message: error.response.data.message || 'Payment initialization failed',
          details: error.response.data
        });
      }
      // Other error
      res.status(500).json({
        status: 'error',
        message: error.message || 'Payment initialization failed'
      });
    }
  }
);

// Webhook for payment verification
app.post('/webhook',
  webhookLimiter,
  verifyPaystackWebhook,
  async (req, res, next) => {
  try {
    const event = req.body;

    if (event.event === 'charge.success') {
      const paymentData = event.data;

      if (!paymentData.amount || paymentData.amount <= 0) {
        logger.warn('❌ Invalid or zero donation amount:', paymentData.amount);
        return res.status(400).json({
  error: {
    name: 'ValidationError',
    message: 'Invalid donation amount'
  }
});

      }

      const { error, value: validMetadata } = metadataSchema.validate(paymentData.metadata || {});
      if (error) {
        logger.error('❌ Invalid metadata in webhook:', error.details);
        return res.status(400).json({ error: { name: 'ValidationError', message: 'Invalid metadata' } });
      }

      logger.info('✅ Verified Payment:', paymentData.reference);
      const { donorName, ...safeMetadata } = paymentData.metadata || {};
      logger.info('🔎 Payment Metadata:', safeMetadata);

      // Save to database
      await db('donations').insert({
      email: paymentData.customer.email,
      reference: paymentData.reference,
      amount: paymentData.amount,
      currency: paymentData.currency,
      metadata: JSON.stringify(paymentData.metadata),
      created_at: new Date().toISOString() // ✅ ensures proper timestamp
      });

      logger.info('✅ Donation saved to database!');

      // Initialize variables with default values
      let purposeText = 'General Donation';

      // Check if we have staffId or projectId
      // 🛡️ Defensive parsing for metadata IDs
let staffId = null;
let projectId = null;

if (validMetadata) {
  const rawStaffId = validMetadata.staffId;
  const rawProjectId = validMetadata.projectId;

  if (typeof rawStaffId === 'string' && /^\d+$/.test(rawStaffId.trim())) {
    staffId = parseInt(rawStaffId.trim(), 10);
  }

  if (typeof rawProjectId === 'string' && /^\d+$/.test(rawProjectId.trim())) {
    projectId = parseInt(rawProjectId.trim(), 10);
  }
}

let staffName = null;
let projectName = null;

if (staffId !== null) {
  staffName = await getDisplayName('staff', staffId, db);
}

if (projectId !== null) {
  projectName = await getDisplayName('projects', projectId, db);
}

if (staffName && projectName) {
  purposeText = `Staff + Project Support -- ${staffName} & ${projectName}`;
} else if (staffName) {
  purposeText = `Staff Support -- ${staffName}`;
} else if (projectName) {
  purposeText = `Project Support -- ${projectName}`;
} else {
  logger.warn('❌ No valid staffId or projectId in metadata.');
}

      logger.info('Purpose:', purposeText);

      // Send beautiful thank-you email
      const sanitizedDonorName = sanitizeHeader(donorName || '');
      const donorFirstName = sanitizedDonorName.split(' ')[0] || 'Friend';
      const toEmail = sanitizeHeader(paymentData.customer.email);
      const formattedAmount = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: paymentData.currency || 'NGN',
  minimumFractionDigits: 2,
}).format(paymentData.amount / 100);

      
      const donationDate = new Date().toLocaleDateString('en-US', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  timeZone: 'UTC'
});


      await sgMail.send({
  to: toEmail,  // Use sanitized email
  from: {
    name: 'Harvest Call Ministries',
    email: 'giving@harvestcallafrica.org'
  },
  subject: sanitizeHeader(`Thank You, ${donorFirstName}! Your Generosity is Making a Difference`),
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Thank You for Your Donation</title>
            <style>
              /* Modern email-friendly CSS */
              body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #f8f9fa;
                margin: 0;
                padding: 0;
              }
              
              .container {
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background: #ffffff;
              }
              
              .header {
                background: linear-gradient(135deg, #003366 0%, #2E7D32 100%);
                color: white;
                padding: 30px;
                text-align: center;
                border-radius: 8px 8px 0 0;
              }
              
              .header-title {
                font-size: 28px;
                font-weight: 700;
                margin-bottom: 10px;
                letter-spacing: -0.5px;
              }
              
              .header-subtitle {
                font-size: 18px;
                font-weight: 300;
                max-width: 500px;
                margin: 0 auto;
                line-height: 1.5;
                color: #fdf5e6;
              }
              
              .content {
                padding: 30px;
              }
              
              .thank-you {
                font-size: 24px;
                color: #003366;
                margin-bottom: 25px;
                font-weight: 700;
                text-align: center;
              }
              
              .highlight {
                color: #E67E22;
                font-weight: 700;
                font-size: 20px;
              }
              
              .details-card {
                background: #fdf5e6;
                padding: 25px;
                border-radius: 12px;
                margin: 25px 0;
                border: 1px solid #f0e6d6;
              }
              
              .detail-row {
                display: flex;
                margin-bottom: 12px;
                padding-bottom: 12px;
                border-bottom: 1px solid #f0e6d6;
              }
              
              .detail-label {
                font-weight: 600;
                color: #8D6E63;
                min-width: 120px;
              }
              
              .detail-value {
                flex: 1;
                font-weight: 500;
              }
              
              .impact-statement {
                font-style: italic;
                color: #2E7D32;
                margin: 30px 0;
                padding: 20px;
                background: #e8f5e9;
                border-radius: 8px;
                text-align: center;
                font-size: 18px;
                border-left: 4px solid #2E7D32;
              }
              
              .cta-button {
                display: block;
                width: 70%;
                max-width: 300px;
                margin: 30px auto;
                padding: 16px;
                background: #E67E22;
                color: white !important;
                text-align: center;
                text-decoration: none;
                font-weight: 700;
                font-size: 18px;
                border-radius: 8px;
                transition: all 0.3s ease;
              }
              
              .cta-button:hover {
                background: #d35400;
                transform: translateY(-2px);
              }
              
              .signature {
                margin-top: 30px;
                border-top: 1px solid #e0e0e0;
                padding-top: 20px;
                text-align: center;
              }
              
              .footer {
                text-align: center;
                margin-top: 40px;
                font-size: 14px;
                color: #8D6E63;
              }
              
              .footer a {
                color: #2E7D32;
                text-decoration: none;
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1 class="header-title">Thank You for Your Support!</h1>
                <p class="header-subtitle">Your donation is helping transform lives across Africa</p>
              </div>
              
              <div class="content">
                <h2 class="thank-you">Thank You, ${escapeHtml(donorFirstName)}!</h2>
                
                <p>We're incredibly grateful for your generous donation of <span class="highlight">${formattedAmount}</span> to Harvest Call Ministries. Your support is making a tangible difference in advancing God's kingdom across Africa and beyond.</p>
                
                <div class="details-card">
                  <div class="detail-row">
                    <div class="detail-label">Reference:</div>
                    <div class="detail-value">${paymentData.reference}</div>
                  </div>
                  <div class="detail-row">
                    <div class="detail-label">Donation Type:</div>
                    <div class="detail-value">${validMetadata.donationType || 'General'}</div>
                  </div>
                  <div class="detail-row">
                    <div class="detail-label">Purpose:</div>
                    <div class="detail-value">${purposeText}</div>
                  </div>
                  <div class="detail-row">
                    <div class="detail-label">Date:</div>
                    <div class="detail-value">${donationDate}</div>
                  </div>
                </div>
                
                <p class="impact-statement">"Your partnership enables indigenous missionaries to bring the Gospel to unreached communities."</p>
                
                <p>We've attached your tax receipt to this email for your records. This receipt may be used for tax deduction purposes according to your local regulations.</p>
                
                <a href="https://harvestcallafrica.org/impact" class="cta-button">
                  See How Your Donation Makes an Impact
                </a>
                
                <div class="signature">
                  <p>With heartfelt gratitude,</p>
                  <p><strong>The Harvest Call Ministries Team</strong></p>
                  <p>Abuja, Nigeria</p>
                </div>
              </div>
              
              <div class="footer">
                <p>Harvest Call Ministries &bull; Abuja, Nigeria</p>
                <p><a href="https://harvestcallafrica.org">harvestcallafrica.org</a> &bull; <a href="mailto:info@harvestcallafrica.org">info@harvestcallafrica.org</a></p>
                <p>You're receiving this email because you made a donation to Harvest Call Ministries.</p>
              </div>
            </div>
          </body>
          </html>
        `
      });

      logger.info('📧 Beautiful thank-you email sent via SendGrid!');
    }

     res.status(200).send('Webhook received');
  } catch (error) {
    logger.error('❌ Error processing webhook:', error.message);
    res.status(400).json({ error: error.message });
  }
});



// Admin Donations Fetches all donations from the database
app.get('/admin/donations', async (req, res, next) => {
  try {
    const donations = await db('donations').orderBy('id', 'desc');

    let tableRows = donations.map(d => {
      // ✅ Safe metadata parsing
      let metadata = {};
      try {
        metadata = typeof d.metadata === 'string'
          ? JSON.parse(d.metadata)
          : (d.metadata || {});
      } catch (err) {
        logger.error('❌ Invalid metadata JSON:', d.metadata);
      }

      // ✅ Escape HTML for all user-generated fields
      const donorName = escapeHtml(metadata.donorName || '-');
      const purpose = escapeHtml(metadata.purpose || '-');
      const donationType = escapeHtml(metadata.donationType || '-');
      const email = escapeHtml(d.email || '-');
      const reference = d.reference;
      const referenceEscaped = escapeHtml(reference);
      const currency = d.currency || 'NGN';
      const amount = formatCurrency(d.amount, currency);
      const status = 'success';

      const rawDate = d.created_at || d.timestamp;
      let displayDate = 'Unknown';
      try {
        displayDate = new Date(rawDate).toLocaleDateString('en-US', {
          timeZone: 'UTC',
          month: 'short',
          day: 'numeric',
          year: 'numeric'
        });
      } catch {}

      return `
        <tr>
          <td>${escapeHtml(donorName)}</td>
          <td>${email}</td>
          <td>${amount}</td>
          <td>${currency}</td>
          <td>${purpose}</td>
          <td>${donationType}</td>
          <td>${referenceEscaped}</td>
          <td>${displayDate}</td>
          <td><span class="status success">Success</span></td>
          <td class="actions">
            <button class="action-btn"><i class="fas fa-eye"></i></button>
            <button class="action-btn"><i class="fas fa-receipt"></i></button>
          </td>
        </tr>
      `;
    }).join('');

    res.render('admin-donations', {
      cspNonce: res.locals.cspNonce,
      tableRows
    });

  } catch (err) {
    next(err);
  }
});


// Get all active staff
app.get('/staff', async (req, res, next) => {
  try {
    const staff = await db('staff').where({ active: true }).orderBy('name');
    res.json(staff);
  } catch (error) {
  next(new DatabaseError('Failed to load staff list'));
}
});

// Get all projects
app.get('/projects', async (req, res, next) => {
  try {
    const projects = await db('projects').orderBy('name');
    res.json(projects);
  } catch (error) {
  next(new DatabaseError('Failed to load project list'));
}
});

// Admin Summary Dashboard
app.get('/admin/summary',
  requireAuth,
  cache('5 minutes'),
  async (req, res, next) => {
    try {
      const targetMonth = req.query.month || new Date().toISOString().slice(0, 7);
      const [year, month] = targetMonth.split('-').map(Number);
      const current = new Date(Date.UTC(year, month - 1, 1));
      
      // Validate month format
      if (!/^\d{4}-\d{2}$/.test(targetMonth)) {
        return res.status(400).json({ error: { name: 'ValidationError', message: 'Invalid month format' } });
      }

      const monthStart = new Date(Date.UTC(year, month - 1, 1));
      const monthEnd = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));

      const [allStaff, allProjects, aggregatedData, rawDonations] = await Promise.all([
        db('staff').select('id', 'name', 'active'),
        db('projects').select('id', 'name'),
        db('donations')
          .select(
            db.raw("CASE WHEN metadata->>'staffId' ~ '^\\d+$' THEN (metadata->>'staffId')::integer ELSE NULL END as staff_id"),
            db.raw("CASE WHEN metadata->>'projectId' ~ '^\\d+$' THEN (metadata->>'projectId')::integer ELSE NULL END as project_id"),
            db.raw('SUM(amount) as total_amount'),
            db.raw('COUNT(DISTINCT email) as donor_count')
          )
          .whereBetween('created_at', [monthStart, monthEnd])
          .groupBy('staff_id', 'project_id'),
        db('donations')
          .select('email')
          .whereBetween('created_at', [monthStart, monthEnd])
          .distinct('email')
      ]);

      const staffMap = new Map(allStaff.map(s => [s.id, s]));
      const projectMap = new Map(allProjects.map(p => [p.id, p]));

      const summary = {
        total: 0,
        totalStaff: 0,
        totalProject: 0,
        donors: new Set(rawDonations.map(d => d.email)),
        records: {}
      };

      for (const row of aggregatedData) {
        const amount = row.total_amount / 100;
        summary.total += amount;

        if (row.staff_id && staffMap.has(row.staff_id)) {
          const staff = staffMap.get(row.staff_id);
          if (staff.active) {
            summary.totalStaff += amount;
            const key = `staff-${staff.id}`;
            summary.records[key] = summary.records[key] || {
              label: `Staff – ${staff.name}`,
              total: 0
            };
            summary.records[key].total += amount;
          }
        } else if (row.project_id && projectMap.has(row.project_id)) {
          summary.totalProject += amount;
          const project = projectMap.get(row.project_id);
          const key = `project-${project.id}`;
          summary.records[key] = summary.records[key] || {
            label: `Project – ${project.name}`,
            total: 0
          };
          summary.records[key].total += amount;
        }
      }

      const donorCount = summary.donors.size;
      const avgGift = donorCount ? (summary.total / donorCount).toFixed(2) : 0;

      const prevMonth = new Date(current);
      prevMonth.setUTCMonth(prevMonth.getUTCMonth() - 1);
      const nextMonth = new Date(current);
      nextMonth.setUTCMonth(nextMonth.getUTCMonth() + 1);

      const format = date => `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
      const prev = format(prevMonth);
      const next = format(nextMonth);
      const title = current.toLocaleString('default', {
        year: 'numeric',
        month: 'long',
        timeZone: 'UTC'
      });

      res.render('admin-summary', {
        cspNonce: res.locals.cspNonce,
        summary,
        donorCount,
        avgGift,
        prev,
        next,
        title
      });
    } catch (err) {
      next(err);
    }
  }
);



// View and manage staff accounts (/admin/staff)
app.get('/admin/staff', requireAuth, async (req, res, next) => {
  try {
    const staffList = await db('staff').orderBy('name');
    res.render('admin-staff', {
      staffList,
      cspNonce: res.locals.cspNonce
    });
  } catch (err) {
    next(new DatabaseError('Failed to load staff list'));
  }
});


app.post('/admin/toggle-staff/:id', requireAuth, async (req, res, next) => {
  try {
    // ✅ Fix SQL Injection Vulnerability - Replaced with safe parsing
    const staffId = parseInt(req.params.id);
    if (isNaN(staffId) || staffId <= 0) {
      throw new Error('Invalid staff ID');
    }

    await db.transaction(async trx => {
      const staff = await trx('staff').where('id', staffId).first();
      if (!staff) throw new NotFoundError('Staff not found');

      const newStatus = !staff.active;

      await trx('staff')
        .where('id', staffId)
        .update({
          active: newStatus,
          updated_at: new Date().toISOString()
        });

      await trx('staff_accounts')
        .where('staff_id', staffId)
        .update({
          disabled: !newStatus,
          must_change_password: newStatus ? false : true,
          updated_at: new Date().toISOString()
        });
    });

    res.redirect('/admin/staff');
  } catch (err) {
    next(new DatabaseError('Failed to update staff status'));
  }
});



// View all projects
app.get('/admin/projects', requireAuth, async (req, res, next) => {
  try {
    const projects = await db('projects').orderBy('created_at', 'desc');
    res.render('admin-projects', {
      projects,
      cspNonce: res.locals.cspNonce
    });
  } catch (err) {
    next(new DatabaseError('Could not load project list.'));
  }
});


// Toggle project active status
app.post('/admin/toggle-project/:id', requireAuth, async (req, res, next) => {
  const projectId = req.sanitizedId;
  try {
    const project = await db('projects').where({ id: projectId }).first();
    if (!project) {
      return res.status(404).json({ 
        error: { name: 'NotFoundError', message: 'Project not found.' } 
      });
    }

    await db('projects')
      .where({ id: projectId })
      .update({
        active: !project.active,
        updated_at: new Date().toISOString()
      });

    res.redirect('/admin/projects');
  } catch (err) {
    next(new DatabaseError('Failed to update project'));
  }
});


// GET: Show form to add a new project
app.get('/admin/add-project', requireAuth, (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Add Project - Admin</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 30px; }
          form { background: white; padding: 20px; border-radius: 8px; max-width: 500px; margin: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
          input, textarea, button { width: 100%; padding: 10px; margin-top: 10px; font-size: 16px; }
          button { background: #003366; color: white; border: none; cursor: pointer; margin-top: 20px; }
          button:hover { background: #002244; }
          .back-link { display: block; text-align: center; margin-top: 20px; text-decoration: none; color: #003366; }
        </style>
      </head>
      <body>
        <h2 style="text-align:center;">🛠 Add New Project</h2>
        const token = res.locals.csrfToken;
...
<form method="POST" action="/admin/add-project">
  <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
          <input type="text" name="name" placeholder="Project Name" required />
          <textarea name="description" placeholder="Project Description (optional)"></textarea>
          <button type="submit">Add Project</button>
        </form>
        <a href="/admin/projects" class="back-link">← Back to Project List</a>
      </body>
    </html>
  `);
});

// POST: Handle form submission
app.post('/admin/add-project',
  requireAuth,
  [
    body('name').isString().trim().notEmpty().withMessage('Project name is required'),
    body('description').optional().isString().trim()
  ],
  validateRequest,
  async (req, res, next) => {
    const { name, description } = req.body;

    try {
      await db('projects').insert({
        name,
        description,
        active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      res.redirect('/admin/projects');
    } catch (err) {
      next(new DatabaseError('Failed to add project.'));
    }
  }
);


// Show the form to add new staff + create account
app.get('/admin/add-staff-account', requireAuth, async (req, res, next) => {
  try {
    const form = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Add Staff Account</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #f5f5f5; }
        form { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: auto; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 8px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; }
        button { background: #003366; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #002244; }
      </style>
    </head>
    <body>
      <h2 style="text-align:center;">Add New Staff + Login Account</h2>
      const token = res.locals.csrfToken;
...
<form method="POST" action="/admin/add-staff-account">
  <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
        <label>Name</label>
        <input type="text" name="name" required />

        <label>Email</label>
        <input type="email" name="email" required />

        <label>Password</label>
        <input type="password" name="password" required />

        <button type="submit">Create Account</button>
      </form>
    </body>
    </html>
    `;
    res.send(form);
  } catch (err) {
  next(new DatabaseError('Error loading form.'));
}
});

// Handle form submission to add staff + create login
app.post('/admin/add-staff-account',
  requireAuth,
  [
    body('name').isString().trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
  ],
  validateRequest,
  async (req, res, next) => {
    try {
      const { name, password } = req.body;
      const email = req.body.email.toLowerCase();

      const existing = await db('staff').where({ email }).first();
      if (existing) {
        return res.status(400).send(`
          <div style="font-family: Arial; padding: 30px;">
            <h2 style="color: red;">Staff Already Exists</h2>
            <p>A staff with email <strong>${email}</strong> already exists.</p>
            <a href="/admin/add-staff-account" style="color: #003366;">Try Again</a>
          </div>
        `);
      }

      await db.transaction(async trx => {
        const insertedStaff = await trx('staff')
          .insert({ name, email, active: true })
          .returning('id');

        const staffId = insertedStaff[0]?.id || insertedStaff[0];
        if (!staffId) throw new DatabaseError('Failed to retrieve staff ID after insertion');

        const password_hash = await bcrypt.hash(password, BCRYPT_COST);
        await trx('staff_accounts').insert({
          email,
          password_hash,
          staff_id: staffId,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
      });

      res.send(`
        <div style="font-family: Arial; padding: 30px;">
          <h2 style="color: #2E7D32;">✅ Staff Account Created</h2>
          <p>${escapeHtml(name)} with login <strong>${escapeHtml(email)}</strong> has been added successfully.</p>
          <a href="/admin/add-staff-account" style="display:inline-block;margin-top:20px;background:#003366;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Add Another</a>
        </div>
      `);
    } catch (err) {
      next(new DatabaseError('Error creating staff account'));
    }
  }
);



// Show assign projects form
app.get('/admin/assign-projects', requireAuth, async (req, res, next) => {
  try {
    const staff = await db('staff').where({ active: true }).orderBy('name');
    const projects = await db('projects').where({ active: true }).orderBy('name');
    res.render('assign-projects', {
      csrfToken: res.locals.csrfToken,
      staff,
      projects,
      cspNonce: res.locals.cspNonce
    });
  } catch (err) {
    next(new DatabaseError('Failed to load project assignment form.'));
  }
});


// Handle project assignment
app.post('/admin/assign-projects', requireAuth, async (req, res, next) => {
  const staffId = req.body.staffId;
  const selectedProjects = Array.isArray(req.body.projectIds)
    ? req.body.projectIds
    : [req.body.projectIds]; // Handles single or multiple

  try {
    const now = new Date().toISOString();
const assignments = selectedProjects.map(pid => ({
  staff_id: staffId,
  project_id: pid,
  created_at: now
}));


    // ✅ Wrap both delete + insert in a transaction
    await db.transaction(async trx => {
      await trx('staff_projects').where({ staff_id: staffId }).del();

      if (assignments.length) {
        await trx('staff_projects').insert(assignments);
      }
    });

    res.redirect('/admin/projects'); // ✅ Don’t forget response!
  } catch (err) {
  next(new DatabaseError('Failed to assign projects.'));
}
});


// ✅ Login form route (GET) -- ensure CSRF token is generated
app.get('/login', (req, res) => {
  res.render('login', {
    csrfToken: res.locals.csrfToken,
    cspNonce: res.locals.cspNonce,
    error: req.query.error || null
  });
});



// Login Handler
app.post(
  '/login',
  (req, res, next) => {
    // Log session info for debugging
    logger.debug(`[LOGIN] Session ID: ${req.sessionID}`);
    logger.debug(`[LOGIN] CSRF Secret: ${req.session.csrfSecret}`);
    logger.debug(`[LOGIN] Body _csrf: ${req.body._csrf}`);
    logger.debug(`[LOGIN] Cookie csrf-token: ${req.cookies['csrf-token']}`);
    next();
  },
  (req, res, next) => {
    // Wrap doubleCsrfProtection to log errors
    doubleCsrfProtection(req, res, (err) => {
      if (err) {
        logger.warn(`[CSRF] doubleCsrfProtection error: ${err.message}`);
      }
      next(err);
    });
  },
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail().withMessage('Email is required'),
    body('password').isString().notEmpty().withMessage('Password is required')
  ],
  validateRequest,
  async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const normalizedEmail = email.toLowerCase();

      // Fetch account from DB
      const account = await db('staff_accounts')
        .where(db.raw('LOWER(email)'), normalizedEmail)
        .first();

      if (!account) {
        return res.status(401).json({
          error: { name: 'Unauthorized', message: 'Invalid email or password.' }
        });
      }

      if (account.disabled) {
        return res.status(403).json({
          error: { name: 'Forbidden', message: 'This account has been disabled.' }
        });
      }

      const isMatch = await bcrypt.compare(password, account.password_hash);
      if (!isMatch) {
        return res.status(401).json({
          error: { name: 'Unauthorized', message: 'Invalid email or password.' }
        });
      }

      // ✅ Success: regenerate session and redirect
      req.session.regenerate(err => {
        if (err) return next(new AppError('Session regeneration failed', 500));
        req.session.staffId = account.staff_id;
        req.session.accountId = account.id;
        // Do NOT set csrfSecret here! Let the CSRF secret middleware handle it on the next GET
        res.redirect(303, '/staff-dashboard');
      });
    } catch (err) {
      next(err);
    }
  }
);



// Password reset request endpoint
app.get('/forgot-password', (req, res) => {
  const csrfToken = res.locals.csrfToken;
  const cspNonce = res.locals.cspNonce;
  res.render('forgot-password', { csrfToken, cspNonce });
});

// ✅ Forgot Password Route - POST
app.post('/forgot-password', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
], validateRequest, async (req, res, next) => {
  const { email } = req.body;
  try {
    const normalizedEmail = email.toLowerCase();
    const account = await db('staff_accounts').where('email', normalizedEmail).first();

    if (account) {
      const token = jwt.sign({ id: account.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const resetLink = `${process.env.FRONTEND_BASE_URL}/reset-password?token=${token}`;

      if (process.env.SENDGRID_API_KEY) {
        sgMail.setApiKey(process.env.SENDGRID_API_KEY);
        await sgMail.send({
          to: normalizedEmail,
          from: { name: 'Harvest Call Support', email: 'support@harvestcallafrica.org' },
          subject: 'Password Reset Instructions',
          html: `...your-html-here...`
        });
      }

      logger.info(`Password reset link for ${normalizedEmail}: ${resetLink}`);
    }

    // Always show success message regardless of account existence
    res.send(`
      <html>
        <body style="text-align:center; padding:40px;">
          <h2>Password Reset Request Received</h2>
          <p>If an account exists for <strong>${normalizedEmail}</strong>, you'll receive instructions shortly.</p>
          <a href="/login" class="btn">Return to Login</a>
        </body>
      </html>
    `);

  } catch (err) {
    logger.error('Password reset request error:', err);
    next(new DatabaseError('Failed to process password reset request'));
  }
});

// ✅ Password Reset Form - Added for token-based password reset
app.get('/reset-password', (req, res) => {
  const token = req.query.token;
  const csrfToken = res.locals.csrfToken;

  if (!token) {
    return res.status(400).send(`
      <div style="text-align:center; padding:40px;">
        <h2 style="color:#d32f2f;">Invalid Reset Link</h2>
        <p>The password reset link is missing the required token.</p>
        <p>Please request a new <a href="/forgot-password">password reset</a>.</p>
      </div>
    `);
  }

  res.render('reset-password', { csrfToken, token });
});

// 🔐 Staff Authentication Middleware
const requireStaffAuth = (req, res, next) => {
  if (req.session && req.session.staffId) {
    return next();
  }
  res.redirect('/login');
};

// ✅ Change Password - GET
app.get('/change-password', requireStaffAuth, (req, res) => {
  const token = res.locals.csrfToken;
  const form = `
    <form method="POST" action="/change-password">
      <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
      <input type="password" name="old_password" placeholder="Current Password" required />
      <input type="password" name="new_password" placeholder="New Password" required />
      <input type="password" name="confirm_password" placeholder="Confirm New Password" required />
      <button type="submit">Update Password</button>
    </form>
  `;
  res.send(form);
});


// ✅ Change Password - POST
app.post('/change-password', requireStaffAuth, [
  body('old_password').notEmpty().withMessage('Current password is required'),
  body('new_password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('confirm_password').custom((value, { req }) => {
    if (value !== req.body.new_password) throw new Error('Passwords do not match');
    return true;
  })
], validateRequest, async (req, res, next) => {
  const { old_password, new_password } = req.body;
  const staffId = req.session.staffId;

  try {
    const account = await db('staff_accounts').where('staff_id', staffId).first();
    const isMatch = await bcrypt.compare(old_password, account.password_hash);

    if (!isMatch) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }

    const hash = await bcrypt.hash(new_password, BCRYPT_COST);
    await db('staff_accounts')
      .where('staff_id', staffId)
      .update({ password_hash: hash, updated_at: new Date().toISOString() });

    req.session.regenerate((err) => {
      if (err) return next(new AppError('Session regeneration failed.', 500));
      req.session.staffId = account.staff_id;
      req.session.accountId = account.id;
      res.redirect('/staff-dashboard');
    });

  } catch (err) {
    next(new DatabaseError('Password change failed.'));
  }
});



// ✅ Password Reset Form - Added for token-based password reset
app.get('/reset-password', (req, res) => {
  const token = req.query.token;
  const csrfToken = res.locals.csrfToken;
  
  if (!token) {
    return res.status(400).send(`
      <div style="text-align:center; padding:40px;">
        <h2 style="color:#d32f2f;">Invalid Reset Link</h2>
        <p>The password reset link is missing the required token.</p>
        <p>Please request a new <a href="/forgot-password">password reset</a>.</p>
      </div>
    `);
  }

  res.send(`
    <html>
    <head>
      <title>Reset Password</title>
      <style>
        body { font-family: Arial; padding: 40px; background: #f5f5f5; }
        form { background: white; padding: 30px; max-width: 400px; margin: 0 auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #003366; text-align: center; margin-bottom: 20px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #2E7D32; color: white; padding: 12px; width: 100%; border: none; border-radius: 4px; cursor: pointer; }
        .info { background: #e8f5e9; padding: 10px; border-radius: 4px; margin-bottom: 15px; text-align: center; }
        .error { 
          color: #d32f2f; 
          text-align: center; 
          margin: 10px 0; 
          display: none; /* Initially hidden */
        }
      </style>
    </head>
    <body>
      <form method="POST" action="/reset-password" id="resetForm">
        <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
        <input type="hidden" name="token" value="${escapeHtml(token)}" />
        <h2>Reset Your Password</h2>
        <div class="info">
          <i class="fas fa-lock"></i> Create a new password
        </div>
        <input type="password" name="newPassword" id="newPassword" placeholder="New Password" required minlength="6" />
        <input type="password" name="confirmPassword" id="confirmPassword" placeholder="Confirm New Password" required minlength="6" />
        <div id="passwordError" class="error">
          <i class="fas fa-exclamation-circle"></i> Passwords do not match!
        </div>
        <button type="submit">Reset Password</button>
      </form>
      
      <script>
        document.getElementById('resetForm').addEventListener('submit', function(e) {
          const newPass = document.getElementById('newPassword');
          const confirmPass = document.getElementById('confirmPassword');
          const errorDiv = document.getElementById('passwordError');
          
          if (newPass.value !== confirmPass.value) {
            e.preventDefault(); // Stop form submission
            
            // Show error message
            errorDiv.style.display = 'block';
            
            // Highlight fields
            newPass.style.borderColor = '#d32f2f';
            confirmPass.style.borderColor = '#d32f2f';
            
            // Focus on first password field
            newPass.focus();
          } else {
            // Hide error if previously shown
            errorDiv.style.display = 'none';
            newPass.style.borderColor = '';
            confirmPass.style.borderColor = '';
          }
        });
      </script>
    </body>
    </html>
  `);
});

// Staff Dashboard Route
app.get('/staff-dashboard', requireStaffAuth, async (req, res, next) => {
  try {
    const staffId = req.session.staffId;
    const monthParam = req.query.month;

    const staff = await db('staff').where('id', staffId).first();
    if (!staff) {
      logger.error(`❌ Staff not found: ${staffId}`);
      return res.status(404).send('Staff not found');
    }

    const today = new Date();
    const current = monthParam
      ? new Date(`${monthParam}-01T00:00:00.000Z`)
      : new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1));
    const monthKey = current.toLocaleString('default', {
      year: 'numeric',
      month: 'long',
      timeZone: 'UTC'
    });

    const monthStart = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), 1));
    const monthEnd = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() + 1, 0, 23, 59, 59, 999));

    const donations = await db('donations')
      .where('metadata->>staffId', staffId.toString())
      .whereBetween('created_at', [monthStart, monthEnd])
      .orderBy('created_at', 'desc');

    const filtered = donations.filter(d => {
      try {
        const rawDate = d.created_at || d.timestamp;
        if (!rawDate) return false;

        const parsedDate = new Date(rawDate);
        if (!(parsedDate >= monthStart && parsedDate <= monthEnd)) return false;

        const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
        return metadata.staffId == staffId;
      } catch (err) {
        logger.error('❌ Bad donation entry:', d);
        return false;
      }
    });

    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 ? (totalAmount / donorCount).toFixed(2) : 0;

    const formatMonth = date =>
      `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
    const prev = formatMonth(new Date(current.getUTCFullYear(), current.getUTCMonth() - 1, 1));
    const next = formatMonth(new Date(current.getUTCFullYear(), current.getUTCMonth() + 1, 1));

    res.render('staff-dashboard', {
      cspNonce: res.locals.cspNonce,
      staff,
      donations: filtered,
      donorCount,
      avgDonation,
      totalAmount,
      prev,
      next,
      title: monthKey
    });

  } catch (err) {
    logger.error('❌ Staff dashboard error:', err);
    next(new AppError('Failed to load staff dashboard', 500));
  }
});


// Project-Specific Dashboard
// 🔐 Middleware to check staff access to project
const checkProjectAccess = async (req, res, next) => {
  try {
    const staffId = req.session?.staffId;
    const projectId = req.query.projectId;

    // Validate session
    if (!staffId) {
      return res.status(401).send('Authentication required');
    }

    // Validate projectId
    if (!projectId) {
      return res.status(400).send('Project ID is required');
    }

    // Ensure numeric
    const numericProjectId = parseInt(projectId);
    if (isNaN(numericProjectId)) {
      return res.status(400).send('Invalid Project ID');
    }

    // Check database for access
    const assignment = await db('staff_projects')
      .where({
        staff_id: staffId,
        project_id: numericProjectId
      })
      .first();

    if (!assignment) {
      logger.warn(`🚫 Unauthorized project access: Staff ${staffId} to Project ${projectId}`);
      return res.status(403).send('You do not have permission to view this project');
    }

    // Attach project ID to request
    req.projectId = numericProjectId;
    next();
  } catch (err) {
    next(new AppError('Server error during project authorization', 500));
  }
};

// ✅ Route: /project-dashboard
app.get('/project-dashboard', requireStaffAuth, checkProjectAccess, async (req, res, next) => {
  try {
    const projectId = req.projectId;
    const monthParam = req.query.month;

    if (!projectId) {
      return res.status(400).send('Missing projectId');
    }

    const project = await db('projects').where('id', projectId).first();
    if (!project) return res.status(404).send('Project not found');

    const current = monthParam
      ? new Date(`${monthParam}-01T00:00:00.000Z`)
      : new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1));

    const monthKey = current.toLocaleString('default', {
      year: 'numeric',
      month: 'long',
      timeZone: 'UTC'
    });

    const monthStart = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), 1));
    const monthEnd = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() + 1, 0, 23, 59, 59, 999));

    const donations = await db('donations')
      .whereBetween('created_at', [monthStart.toISOString(), monthEnd.toISOString()])
      .andWhereRaw(`metadata->>'projectId' = ?`, [projectId.toString()])
      .orderBy('created_at', 'desc');

    const filtered = donations.filter(d => {
      try {
        const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
        return String(metadata.projectId) === String(projectId);
      } catch (err) {
        logger.error('❌ Bad metadata in donation ID', d.id, ':', d.metadata);
        return false;
      }
    });

    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 ? (totalAmount / donorCount).toFixed(2) : 0;

    const prevDate = new Date(current);
    prevDate.setUTCMonth(prevDate.getUTCMonth() - 1);
    const prev = `${prevDate.getUTCFullYear()}-${String(prevDate.getUTCMonth() + 1).padStart(2, '0')}`;

    const nextDate = new Date(current);
    nextDate.setUTCMonth(nextDate.getUTCMonth() + 1);
    const next = `${nextDate.getUTCFullYear()}-${String(nextDate.getUTCMonth() + 1).padStart(2, '0')}`;

    // ✅ Render EJS dashboard
    res.render('project-dashboard', {
      cspNonce: res.locals.cspNonce,
      project,
      donations: filtered,
      totalAmount,
      donorCount,
      avgDonation,
      title: monthKey,
      prev,
      next,
      projectId
    });

  } catch (err) {
    next(new AppError('Failed to load project dashboard', 500));
  }
});



// Get projects accessible to current staff
app.get('/api/accessible-projects', requireStaffAuth, async (req, res, next) => {
  try {
    const staffId = req.session.staffId;
    const projects = await db('projects')
      .join('staff_projects', 'projects.id', 'staff_projects.project_id')
      .where('staff_projects.staff_id', staffId)
      .select('projects.id', 'projects.name', 'projects.description');

    res.json(projects);
  } catch (err) {
  next(new DatabaseError('Failed to load accessible projects'));
}
});


// ✅ Custom error for bad tokens
// Replace the existing CSRF error handler with this simplified version
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN' || err.name === 'ForbiddenError') {
    logger.warn('⚠️ CSRF validation failed:', err.message);
    // Return JSON for API endpoints, otherwise redirect
    const apiLike = req.path.startsWith('/initialize-payment') || req.path.startsWith('/webhook') || req.path.startsWith('/api/') || req.path.startsWith('/staff') || req.path.startsWith('/projects');
    if (apiLike || (req.headers.accept && req.headers.accept.includes('application/json'))) {
      return res.status(403).json({
        error: {
          name: 'ForbiddenError',
          message: 'Invalid CSRF token. Please refresh and try again.'
        }
      });
    }
    return res.redirect('/login?error=Invalid%20CSRF%20token.%20Please%20refresh%20and%20try%20again.');
  }
  next(err);
});

// Then move this to the very end of your middleware chain:
app.use((err, req, res, next) => {
  // 🧠 Special proxy error
  if (err.code === 'ERR_ERL_UNEXPECTED_X_FORWARDED_FOR') {
    return res.status(500).json({
      error: {
        name: 'ProxyError',
        message: 'Proxy configuration error',
        details: 'Server is behind a proxy but not configured to trust it'
      }
    });
  }

  logger.error('❌ Global error handler:', err);

  // Always return JSON for API endpoints
  const apiLike = req.path.startsWith('/initialize-payment') || req.path.startsWith('/webhook') || req.path.startsWith('/api/') || req.path.startsWith('/staff') || req.path.startsWith('/projects');
  if (apiLike || (req.headers.accept && req.headers.accept.includes('application/json'))) {
    const status = err.status || 500;
    const response = {
      error: {
        name: err.name || 'InternalError',
        message: err.message || 'An unexpected error occurred'
      }
    };
    if (process.env.NODE_ENV === 'development') {
      response.error.stack = err.stack;
    }
    return res.status(status).json(response);
  }

  // Otherwise render fallback error page
  res.status(500).render('error', {
    cspNonce: res.locals.cspNonce,
    message: 'An unexpected error occurred. Please try again later.'
  });
});


// ✅ Index maintenance logic with locking
let isMaintenanceRunning = false;
async function runIndexMaintenance() {
  if (process.env.NODE_ENV === 'production') {
    if (isMaintenanceRunning) return;
    isMaintenanceRunning = true;
    try {
      logger.info('🔄 Starting index maintenance...');
      await db.raw('ANALYZE donations');
      logger.info('✅ ANALYZE donations completed');
      const utcHours = new Date().getUTCHours();
      if (utcHours >= 1 && utcHours <= 4) {
        await db.raw('REINDEX TABLE donations');
        logger.info('🔄 REINDEX donations completed');
      }
    } catch (err) {
      logger.error('❌ Index maintenance failed:', err.message);
      if (process.env.SENDGRID_API_KEY && process.env.ADMIN_EMAIL) {
        await sgMail.send({
          to: process.env.ADMIN_EMAIL,
          from: 'server@harvestcallafrica.org',
          subject: 'Index Maintenance Failed',
          text: `Error: ${err.message}`
        });
      }
    } finally {
      isMaintenanceRunning = false;
    }
  }
}

// ✅ Server startup
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    logger.info('⏳ Initializing database...');
    await initializeDatabase();

    logger.info('🔧 Running initial index maintenance...');
    await runIndexMaintenance();

    
    logger.info('🚀 Starting Express server...');
    app.listen(PORT, () => {
      logger.info(`✅ Server is running on port ${PORT}`);
      setInterval(() => {
        const now = new Date();
        if (now.getUTCDay() === 0 && now.getUTCHours() === 2) {
          runIndexMaintenance();
        }
      }, 60 * 60 * 1000);
    });
  } catch (err) {
    logger.error('❌ Failed to start server:', err);
    try {
      await notifyAdmin('Critical App Crash', err.stack);
    } catch (notifyErr) {
      logger.warn('Failed to notify admin of startup failure.');
    }
    process.exit(1);
  }
}


process.on('SIGINT', async () => {
  try {
    await notifyAdmin('🔻 Server Shutdown', 'The server is shutting down via SIGINT.');
  } catch (e) {
    logger.warn('Failed to notify admin of shutdown.');
  }
  await db.destroy();
  process.exit(0);
});

startServer();
