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
const { param, body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const apicache = require('apicache');
const cache = apicache.middleware;
const formatCurrency = require('./utils/formatCurrency');
const logger = require('./utils/logger');
const { notifyAdmin } = require('./utils/alerts');
const { doubleCsrf } = require('csrf-csrf');
const jwt = require('jsonwebtoken');
const path = require('path');


const app = express();
app.set('trust proxy', true);  // Trust Render.com proxies
logger.info('NODE_ENV:', process.env.NODE_ENV);

// ✅ CORS Configuration - Added per security recommendation
app.use(cors({ 
  origin: process.env.FRONTEND_URL || process.env.FRONTEND_BASE_URL,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Nonce generation middleware
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('hex');
  next();
});

// ✅ Helmet Activation - Added for enhanced security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
        "cdnjs.cloudflare.com"
      ],
      styleSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
        "cdnjs.cloudflare.com"
      ],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "cdnjs.cloudflare.com"],
      connectSrc: ["'self'", process.env.PAYSTACK_API_URL || "https://api.paystack.co"]
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'same-origin' },
  frameguard: { action: 'deny' },      // Block iframe embedding
  noSniff: true,                       // Prevent MIME type sniffing
  ieNoOpen: true,                      // Disable IE file open
  xssFilter: true                      // Enable XSS filter
}));


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

app.use(bodyParser.urlencoded({ extended: true })); // Handle form submissions
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Preserve raw body for webhook verification
  }
}));

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

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// MISSING: Session middleware configuration
app.use(session({
  store: new pgSession({ pool: pgPool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET, // Must be set in .env
  resave: false,
  saveUninitialized: false,
  cookie: { 
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  httpOnly: true,
  maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
}
}));


const { doubleCsrfProtection, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  cookieName: "__Host-hc-csrf-token",
  cookieOptions: {
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
  },
});

// Apply CSRF protection middleware globally (GET + POST)
app.use(doubleCsrfProtection);

// Optional: catch CSRF errors nicely
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    console.warn("⚠️ Invalid CSRF token");
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  next(err);
});


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

// ✅ Validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: {
        name: 'ValidationError',
        message: 'Validation failed',
        details: errors.array()
      }
    });
  }
  next();
};

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

// ✅ Basic Auth Middleware
const requireAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Dashboard"');
    return res.status(401).send('Authentication required.');
  }
  const base64Credentials = auth.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');
  if (
    username === process.env.DASHBOARD_USER &&
    password === process.env.DASHBOARD_PASS
  ) return next();
  res.set('WWW-Authenticate', 'Basic realm="Dashboard"');
  return res.status(401).send('Access denied');
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

  app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'donation-form.html'), {
  headers: {
    'Content-Type': 'text/html'
  }
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
  async (req, res, next) => {
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
    next(new DatabaseError('Payment initialization failed'));
  }
});

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
      const status = 'success'; // Later: make dynamic if needed

      // ✅ Safe date handling with fallback
      const rawDate = d.created_at || d.timestamp;
      let displayDate = 'Unknown';
      try {
        displayDate = new Date(rawDate).toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric', year: 'numeric'
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

    res.send(`
      
      <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Donations Admin Dashboard</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
  <style>
    :root {
      --primary: #003366;
      --secondary: #2E7D32;
      --accent: #E67E22;
      --light-bg: #f8f9fa;
      --border: #dee2e6;
      --text: #333;
      --danger: #dc3545;
    }

    body {
      background-color: var(--light-bg);
      color: var(--text);
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      margin: 0;
      padding: 0;
    }

    .admin-container {
      max-width: 1400px;
      margin: auto;
      padding: 20px;
    }

    .admin-header {
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      color: white;
      padding: 20px;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }

    .admin-title {
      display: flex;
      align-items: center;
      gap: 15px;
    }

    .admin-title i {
      font-size: 2rem;
      background: rgba(255, 255, 255, 0.2);
      padding: 12px;
      border-radius: 50%;
    }

    .admin-controls {
      display: flex;
      gap: 10px;
    }

    .admin-btn {
      padding: 10px 16px;
      background: white;
      color: var(--primary);
      border: none;
      border-radius: 5px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .admin-btn:hover {
      background: #e6f7e9;
    }

    .admin-btn.logout {
      background: var(--danger);
      color: white;
    }

    .admin-btn.logout:hover {
      background: #c82333;
    }

    .donations-table {
      background: white;
      border-radius: 8px;
      overflow-x: auto;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 1000px;
    }

    thead {
      background: var(--primary);
      color: white;
    }

    th, td {
      padding: 14px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      font-size: 0.95rem;
    }

    tbody tr:nth-child(even) {
      background-color: #f9f9f9;
    }

    .status {
      display: inline-block;
      padding: 5px 10px;
      border-radius: 12px;
      font-size: 0.85rem;
      font-weight: 500;
    }

    .status.success {
      background: #d4edda;
      color: #155724;
    }

    .actions {
      display: flex;
      gap: 8px;
    }

    .action-btn {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      border: none;
      background: #e9ecef;
      color: var(--text);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .action-btn:hover {
      background: var(--accent);
      color: white;
    }
  </style>
</head>
<body>
  <div class="admin-container">
    <div class="admin-header">
      <div class="admin-title">
        <i class="fas fa-hand-holding-heart"></i>
        <h1>Donation Records - Harvest Call Africa</h1>
      </div>
      <div class="admin-controls">
        <button class="admin-btn"><i class="fas fa-download"></i> Export CSV</button>
        <button class="admin-btn logout"><i class="fas fa-sign-out-alt"></i> Logout</button>
      </div>
    </div>

    <div class="donations-table">
      <table>
        <thead>
          <tr>
            <th>Donor</th>
            <th>Email</th>
            <th>Amount</th>
            <th>Currency</th>
            <th>Purpose</th>
            <th>Type</th>
            <th>Reference</th>
            <th>Date</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    document.querySelector('.admin-btn').addEventListener('click', function () {
      alert('CSV export functionality would be implemented here');
    });

    document.querySelector('.logout').addEventListener('click', function () {
      alert('This would log out the user in a real system');
    });

    document.querySelectorAll('.action-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const icon = this.querySelector('i').className;
        if (icon.includes('fa-eye')) {
          alert('View donation details');
        } else if (icon.includes('fa-receipt')) {
          alert('Download or resend receipt');
        }
      });
    });
  </script>
</body>
</html>`);
  }  catch (error) {
    logger.error('❌ Error loading admin dashboard:', error.message);
    next(new DatabaseError('Failed to load admin donations'));
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

      // PARALLEL DATABASE QUERIES
      const [allStaff, allProjects, aggregatedData, rawDonations] = await Promise.all([
        db('staff').select('id', 'name', 'active'),
        db('projects').select('id', 'name'),
        
        // Aggregated summary data
        db('donations')
          .select(
            db.raw("CASE WHEN metadata->>'staffId' ~ '^\\d+$' THEN (metadata->>'staffId')::integer ELSE NULL END as staff_id"),
            db.raw("CASE WHEN metadata->>'projectId' ~ '^\\d+$' THEN (metadata->>'projectId')::integer ELSE NULL END as project_id"),
            db.raw('SUM(amount) as total_amount'),
            db.raw('COUNT(DISTINCT email) as donor_count')
            )
            .whereBetween('created_at', [monthStart, monthEnd])
             .groupBy('staff_id', 'project_id'),
        
        // Raw donations just for donor emails
        db('donations')
          .select('email')
          .whereBetween('created_at', [monthStart, monthEnd])
          .distinct('email')
      ]);

      // Create lookup maps
      const staffMap = new Map(allStaff.map(s => [s.id, s]));
      const projectMap = new Map(allProjects.map(p => [p.id, p]));

      // Build summary from aggregated data
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

        // Handle staff donations (priority over projects)
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
        }
        // Handle project donations (only if no staff ID)
        else if (row.project_id && projectMap.has(row.project_id)) {
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

      // Replace the existing date calculation with this corrected version:
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
// Generate beautiful HTML dashboard
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Donation Summary Dashboard - Harvest Call Ministries</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #003366;
                --secondary: #2E7D32;
                --accent: #E67E22;
                --light-bg: #f8f9fa;
                --card-bg: #ffffff;
                --text: #333333;
                --text-light: #6c757d;
                --border: #e0e0e0;
                --success: #28a745;
                --info: #17a2b8;
                --shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                background-color: var(--light-bg);
                color: var(--text);
                line-height: 1.6;
                padding: 20px;
            }
            
            .dashboard-container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 1px solid var(--border);
            }
            
            .logo-container {
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .logo {
                width: 50px;
                height: 50px;
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 22px;
            }
            
            .title-container h1 {
                color: var(--primary);
                font-size: 28px;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .title-container p {
                color: var(--text-light);
                font-size: 16px;
            }
            
            .controls {
                display: flex;
                gap: 15px;
            }
            
            .btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 10px 15px;
                background: var(--primary);
                color: white;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 500;
                transition: all 0.3s;
            }
            
            .btn:hover {
                background: #002244;
                transform: translateY(-2px);
                box-shadow: var(--shadow);
            }
            
            .month-nav {
                display: flex;
                align-items: center;
                gap: 15px;
                background: var(--card-bg);
                border-radius: 10px;
                padding: 15px 20px;
                box-shadow: var(--shadow);
                margin-bottom: 30px;
            }
            
            .nav-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: var(--light-bg);
                color: var(--primary);
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 18px;
                text-decoration: none;
            }
            
            .nav-btn:hover {
                background: var(--primary);
                color: white;
                transform: translateY(-2px);
            }
            
            .current-month {
                font-size: 24px;
                font-weight: 600;
                color: var(--primary);
                flex-grow: 1;
                text-align: center;
            }
            
            .kpi-cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .kpi-card {
                background: var(--card-bg);
                border-radius: 15px;
                padding: 25px;
                box-shadow: var(--shadow);
                text-align: center;
                transition: transform 0.3s ease;
            }
            
            .kpi-card:hover {
                transform: translateY(-5px);
            }
            
            .kpi-icon {
                width: 60px;
                height: 60px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 15px;
                font-size: 24px;
            }
            
            .total .kpi-icon {
                background: rgba(40, 167, 69, 0.15);
                color: var(--success);
            }
            
            .staff .kpi-icon {
                background: rgba(231, 126, 34, 0.15);
                color: var(--accent);
            }
            
            .projects .kpi-icon {
                background: rgba(23, 162, 184, 0.15);
                color: var(--info);
            }
            
            .donors .kpi-icon {
                background: rgba(0, 51, 102, 0.15);
                color: var(--primary);
            }
            
            .kpi-card h3 {
                font-size: 16px;
                color: var(--text-light);
                margin-bottom: 10px;
            }
            
            .kpi-card .value {
                font-size: 32px;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .kpi-card .sub-value {
                font-size: 16px;
                color: var(--text-light);
            }
            
            .recipients-table {
                background: var(--card-bg);
                border-radius: 15px;
                overflow: hidden;
                box-shadow: var(--shadow);
                margin-bottom: 30px;
            }
            
            .table-header {
                padding: 20px 25px;
                border-bottom: 1px solid var(--border);
            }
            
            .table-header h2 {
                color: var(--primary);
                font-size: 22px;
                font-weight: 600;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
            }
            
            thead {
                background: #f8fafc;
            }
            
            th {
                padding: 15px 25px;
                text-align: left;
                color: var(--text-light);
                font-weight: 600;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            tbody tr {
                border-bottom: 1px solid var(--border);
                transition: background 0.2s ease;
            }
            
            tbody tr:last-child {
                border-bottom: none;
            }
            
            tbody tr:hover {
                background: #f8fafc;
            }
            
            td {
                padding: 15px 25px;
                font-size: 16px;
            }
            
            .recipient-name {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .recipient-icon {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                background: var(--light-bg);
                color: var(--primary);
                font-size: 18px;
            }
            
            .staff-icon {
                background: rgba(231, 126, 34, 0.1);
                color: var(--accent);
            }
            
            .project-icon {
                background: rgba(23, 162, 184, 0.1);
                color: var(--info);
            }
            
            .amount {
                font-weight: 600;
                color: var(--primary);
            }
            
            .footer {
                text-align: center;
                color: var(--text-light);
                font-size: 14px;
                padding: 20px;
            }
            
            @media (max-width: 768px) {
                .header {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 20px;
                }
                
                .controls {
                    width: 100%;
                    justify-content: center;
                }
                
                .month-nav {
                    flex-wrap: wrap;
                }
                
                .kpi-cards {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="dashboard-container">
            <div class="header">
                <div class="logo-container">
                    <div class="logo">
                        <i class="fas fa-hands-helping"></i>
                    </div>
                    <div class="title-container">
                        <h1>Donation Summary Dashboard</h1>
                        <p>${escapeHtml('Harvest Call Ministries - Monthly Contributions Report')}</p>
                    </div>
                </div>
                <div class="controls">
                    <a href="/admin/donations" class="btn">
                        <i class="fas fa-list"></i> View All Donations
                    </a>
                </div>
            </div>
            
            <div class="month-nav">
                <a href="/admin/summary?month=${prev}" class="nav-btn">
                    <i class="fas fa-chevron-left"></i>
                </a>
                <div class="current-month">${escapeHtml(title)}</div>
                <a href="/admin/summary?month=${next}" class="nav-btn">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </div>
            
            <div class="kpi-cards">
                <div class="kpi-card total">
                    <div class="kpi-icon">
                        <i class="fas fa-donate"></i>
                    </div>
                    <h3>Total Donations</h3>
                    <div class="value">₦${summary.total.toLocaleString()}</div>
                    <div class="sub-value">All Contributions</div>
                </div>
                
                <div class="kpi-card staff">
                    <div class="kpi-icon">
                        <i class="fas fa-user-friends"></i>
                    </div>
                    <h3>Staff Support</h3>
                    <div class="value">₦${summary.totalStaff.toLocaleString()}</div>
                    <div class="sub-value">Missionary Support</div>
                </div>
                
                <div class="kpi-card projects">
                    <div class="kpi-icon">
                        <i class="fas fa-project-diagram"></i>
                    </div>
                    <h3>Project Funding</h3>
                    <div class="value">₦${summary.totalProject.toLocaleString()}</div>
                    <div class="sub-value">Ministry Projects</div>
                </div>
                
                <div class="kpi-card donors">
                    <div class="kpi-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <h3>Donors</h3>
                    <div class="value">${donorCount}</div>
                    <div class="sub-value">Avg Gift: ₦${avgGift}</div>
                </div>
            </div>
            
            <div class="recipients-table">
                <div class="table-header">
                    <h2><i class="fas fa-list"></i> Recipient Breakdown</h2>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Recipient</th>
                            <th>Amount</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${Object.values(summary.records).map(r => `
                            <tr>
                                <td>
                                    <div class="recipient-name">
                                        <div class="recipient-icon ${r.label.includes('Staff') ? 'staff-icon' : 'project-icon'}">
                                            <i class="fas ${r.label.includes('Staff') ? 'fa-user' : 'fa-project-diagram'}"></i>
                                        </div>
                                        <div>${escapeHtml(r.label)}</div>
                                    </div>
                                </td>
                                <td class="amount">₦${r.total.toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            
            <div class="footer">
                <p>Harvest Call Ministries • Generated on ${escapeHtml(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }))}</p>
            </div>
        </div>
        
        <script>
            // Add loading indicator during navigation
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.addEventListener('click', function(e) {
                    // Show loading indicator
                    document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;"><div class="logo" style="animation: spin 1s linear infinite;"><i class="fas fa-spinner"></i></div></div>';
                    // Add spinner animation
                    document.head.innerHTML += '<style>@keyframes spin {100% {transform: rotate(360deg);}}</style>';
                });
            });
        </script>
    </body>
    </html>
    `;

    res.send(html);
  } catch (err) {
    logger.error('❌ Summary route error:', err.message, err.stack);
    next(err);
  }
});

// View and manage staff accounts (/admin/staff)
app.get('/admin/staff', requireAuth, async (req, res, next) => {
  try {
    const staffList = await db('staff').orderBy('name');

    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Manage Staff – Harvest Call Admin</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        body {
          font-family: Arial, sans-serif;
          padding: 40px;
          background: #f8f9fa;
          color: #333;
        }
        h1 {
          color: #003366;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 20px;
        }
        th, td {
          padding: 12px;
          border: 1px solid #ccc;
        }
        th {
          background: #003366;
          color: white;
          text-align: left;
        }
        tr:nth-child(even) {
          background-color: #f2f2f2;
        }
        .btn {
          display: inline-block;
          padding: 6px 12px;
          background-color: #2E7D32;
          color: white;
          text-decoration: none;
          border-radius: 4px;
          font-size: 14px;
        }
        .inactive {
          background-color: #888;
        }
        .top-link {
          margin-bottom: 20px;
          display: inline-block;
        }
      </style>
    </head>
    <body>
      <h1><i class="fas fa-users"></i> Staff Management</h1>
      <a class="top-link btn" href="/admin/add-staff-account">+ Add New Staff</a>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${staffList.map(s => `
            <tr>
              <td>${escapeHtml(s.name)}</td>
              <td>${escapeHtml(s.email)}</td>
              <td>${s.active ? 'Active' : 'Inactive'}</td>
              <td>
                <form method="POST" action="/admin/toggle-staff/${s.id}" style="display:inline;">
                  <button class="btn ${s.active ? 'inactive' : ''}" type="submit">
                    ${s.active ? 'Mark Inactive' : 'Reactivate'}
                  </button>
                </form>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </body>
    </html>
    `;

    res.send(html);
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

    const html = `
    <html>
      <head>
        <title>Manage Projects</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f8f9fa; padding: 30px; }
          h2 { text-align: center; margin-bottom: 20px; }
          table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
          th, td { padding: 12px 16px; border-bottom: 1px solid #ddd; text-align: left; }
          th { background: #003366; color: white; }
          tr:hover { background: #f1f1f1; }
          .status { font-weight: bold; color: green; }
          .inactive { color: red; }
          .btn { padding: 6px 12px; font-size: 14px; background: #E67E22; color: white; border: none; border-radius: 4px; cursor: pointer; }
          .btn:hover { background: #d35400; }
          .top-links { text-align: center; margin-bottom: 20px; }
          .top-links a { margin: 0 10px; text-decoration: none; color: #003366; font-weight: bold; }
        </style>
      </head>
      <body>
        <h2>📁 Project Management</h2>
        <div class="top-links">
          <a href="/admin/summary">← Back to Dashboard</a>
          <a href="/admin/add-project">+ Add New Project</a>
        </div>
        <table>
          <thead>
            <tr>
              <th>Project Name</th>
              <th>Description</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${projects.map(p => `
              <tr>
                <td>${escapeHtml(p.name)}</td>
                <td>${escapeHtml(p.description || '-')}</td>
                <td class="${p.active ? 'status' : 'inactive'}">${p.active ? 'Active' : 'Inactive'}</td>
                <td>
                  <form method="POST" action="/admin/toggle-project/${p.id}" style="display:inline;">
                    <button class="btn" type="submit">${p.active ? 'Mark Inactive' : 'Reactivate'}</button>
                  </form>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </body>
    </html>
    `;

    res.send(html);
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

    const html = `
    <html>
      <head>
        <title>Assign Projects to Staff</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 30px; }
          h2 { text-align: center; margin-bottom: 20px; }
          form { background: white; padding: 20px; max-width: 600px; margin: auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
          label, select, input[type=submit] { display: block; margin-bottom: 15px; width: 100%; }
          select, input[type=submit] { padding: 10px; border-radius: 5px; border: 1px solid #ccc; }
          input[type=checkbox] { margin-right: 10px; }
          .project-item { margin-bottom: 10px; }
          .btn { background: #2E7D32; color: white; border: none; cursor: pointer; }
          .btn:hover { background: #256429; }
          a { display: block; text-align: center; margin-top: 20px; color: #003366; text-decoration: none; }
        </style>
      </head>
      <body>
        <h2>📌 Assign Projects to Staff</h2>
        const token = res.locals.csrfToken;
...
<form method="POST" action="/admin/assign-projects">
  <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
          <label for="staffId">Select Staff</label>
          <select name="staffId" required>
            <option value="">-- Choose Staff --</option>
            ${staff.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('')}
          </select>

          <label>Choose Project(s)</label>
          ${projects.map(p => `
            <div class="project-item">
              <input type="checkbox" name="projectIds" value="${p.id}" id="project-${p.id}" />
              <label for="project-${p.id}">${escapeHtml(p.name)}</label>
            </div>
          `).join('')}

          <input class="btn" type="submit" value="Assign Projects">
        </form>

        <a href="/admin/summary">← Back to Admin Dashboard</a>
      </body>
    </html>
    `;
    res.send(html);
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


// Login Form
app.get('/login', (req, res, next) => {
  try {
    const token = res.locals.csrfToken;
    const html = `
      <html>
      <head>
        <title>Staff Login</title>
        <style>
          body { font-family: Arial; background: #f0f0f0; padding: 40px; }
          form { background: #fff; padding: 20px; max-width: 400px; margin: auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          input { width: 100%; padding: 10px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ccc; }
          button { background: #003366; color: white; padding: 10px; width: 100%; border: none; border-radius: 4px; }
          h2 { text-align: center; margin-bottom: 20px; color: #003366; }
        </style>
      </head>
      <body>
        <form method="POST" action="/login">
          <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
          <h2>Staff Login</h2>
          <input type="email" name="email" placeholder="Email" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Login</button>
          
          <!-- ADDED FORGOT PASSWORD LINK HERE -->
          <p style="text-align: center; margin-top: 15px;">
            <a href="/forgot-password">Forgot your password?</a>
          </p>
        </form>
      </body>
      </html>
    `;
    res.send(html);
  } catch (err) {
    next(err);
  }
});


// Login Handler
app.post('/login',
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

      const account = await db('staff_accounts')
  .where(db.raw('LOWER(email)'), normalizedEmail)
  .first();

if (!account) {
  return res.status(401).json({
    error: {
      name: 'Unauthorized',
      message: 'Invalid email or password.'
    }
  });
}

if (account.disabled) {
  return res.status(403).json({
    error: {
      name: 'Forbidden',
      message: 'This account has been disabled.'
    }
  });
}

const isMatch = await bcrypt.compare(password, account.password_hash);
if (!isMatch) {
  return res.status(401).json({
    error: {
      name: 'Unauthorized',
      message: 'Invalid email or password.'
    }
  });
}

      req.session.regenerate(err => {
        if (err) return next(new AppError('Login failed. Please try again.', 500));
        req.session.staffId = account.staff_id;
        req.session.accountId = account.id;


        return res.redirect('/staff-dashboard');
      });
    } catch (err) {
      next(new DatabaseError('Server error during login.'));
    }
  }
);


// Password reset request endpoint
app.get('/forgot-password', (req, res) => {
  const token = res.locals.csrfToken;
  res.send(`
    <html>
    <head>
      <title>Reset Password</title>
      <style>
        body { font-family: Arial; padding: 40px; background: #f5f5f5; }
        form { background: white; padding: 30px; max-width: 400px; margin: 0 auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #003366; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #003366; color: white; padding: 12px; width: 100%; border: none; border-radius: 4px; cursor: pointer; }
        .footer { text-align: center; margin-top: 20px; }
      </style>
    </head>
    <body>
      <form method="POST" action="/request-password-reset">
        <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
        <h2>Reset Your Password</h2>
        <input type="email" name="email" placeholder="Enter your email" required />
        <button type="submit">Send Reset Instructions</button>
        <div class="footer">
          <a href="/login">Remembered your password?</a>
        </div>
      </form>
    </body>
    </html>
  `);
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
      </style>
    </head>
    <body>
      <form method="POST" action="/reset-password">
        <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
        <input type="hidden" name="token" value="${escapeHtml(token)}" />
        <h2>Reset Your Password</h2>
        <div class="info">
          <i class="fas fa-lock"></i> Create a new password
        </div>
        <input type="password" name="new_password" placeholder="New Password" required minlength="6" />
        <input type="password" name="confirm_password" placeholder="Confirm New Password" required minlength="6" />
        <button type="submit">Reset Password</button>
      </form>
    </body>
    </html>
  `);
});




app.get('/change-password', async (req, res, next) => {
  try {
    const force = req.query.force === 'true';
    const token = res.locals.csrfToken;
    const form = `
      <html>
        <head>
          <title>Change Password</title>
          <style>
            body { font-family: Arial; padding: 30px; background: #f9f9f9; }
            form { max-width: 400px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input, button { display: block; width: 100%; margin-bottom: 15px; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }
            button { background: #003366; color: white; font-weight: bold; cursor: pointer; }
            h2 { color: #003366; }
          </style>
        </head>
        <body>
          <h2>${force ? 'Please change your password before proceeding' : 'Change Password'}</h2>
          <form method="POST" action="/change-password">
            <input type="hidden" name="_csrf" value="${escapeHtml(token)}" />
            <input type="password" name="old_password" placeholder="Current Password" required />
            <input type="password" name="new_password" placeholder="New Password" required />
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required />
            <button type="submit">Update Password</button>
          </form>
        </body>
      </html>
    `;
    res.send(form);
  } catch (err) {
    next(err);
  }
});



app.post('/change-password', async (req, res, next) => {
  const { old_password, new_password, confirm_password } = req.body;
  
  if (!req.session.staffId) {
    return res.status(401).json({ 
      error: { name: 'Unauthorized', message: 'Unauthorized' } 
    });
  }

  try {
    const account = await db('staff_accounts')
      .where('staff_id', req.session.staffId)
      .first();

    if (!account) {
      return res.status(404).json({ 
        error: { name: 'NotFoundError', message: 'Account not found.' } 
      });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({ 
        error: { name: 'ValidationError', message: 'New passwords do not match.' } 
      });
    }

    const isMatch = await bcrypt.compare(old_password, account.password_hash);
    if (!isMatch) {
      return res.status(400).json({ 
        error: { name: 'ValidationError', message: 'Current password is incorrect.' } 
      });
    }

    const newHash = await new Promise((resolve, reject) => {
  bcrypt.hash(new_password, BCRYPT_COST, (err, hash) => {
    if (err) reject(new DatabaseError('Password hashing failed'));
    resolve(hash);
  });
});
    await db('staff_accounts')
      .where('staff_id', req.session.staffId)
      .update({
        password_hash: newHash,
        updated_at: new Date().toISOString()
      });

    req.session.regenerate((err) => {
      if (err) {
        return next(new AppError('Could not reset session after password change.', 500));
      }
      req.session.accountId = account.id;
      req.session.staffId = account.staff_id;
      res.redirect('/staff-dashboard');
    });
  } catch (err) {
    next(new DatabaseError('Password change failed'));
  }

});

// Password reset request endpoint
app.post('/request-password-reset', 
  [body('email').isEmail().normalizeEmail().withMessage('Valid email is required')],
  validateRequest,
  async (req, res, next) => {
    const { email } = req.body;
    
    try {
      const normalizedEmail = email.toLowerCase();
      const account = await db('staff_accounts')
        .where('email', normalizedEmail)
        .first();

      if (account) {
        const token = jwt.sign({ id: account.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const resetLink = `${process.env.FRONTEND_BASE_URL}/reset-password?token=${token}`;
        
        // Send actual email in production
        if (process.env.SENDGRID_API_KEY) {
          sgMail.setApiKey(process.env.SENDGRID_API_KEY);
          await sgMail.send({
            to: normalizedEmail,
            from: {
              name: 'Harvest Call Support',
              email: 'support@harvestcallafrica.org'
            },
            subject: 'Password Reset Instructions',
            html: `
              <!DOCTYPE html>
              <html>
              <head>
                <style>
                  body { font-family: Arial, sans-serif; line-height: 1.6; }
                  .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                  .header { background: #003366; color: white; padding: 20px; text-align: center; }
                  .content { padding: 30px; background: #f8f9fa; }
                  .btn { display: inline-block; padding: 12px 24px; background: #2E7D32; 
                         color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
                  .footer { text-align: center; color: #6c757d; font-size: 14px; margin-top: 30px; }
                </style>
              </head>
              <body>
                <div class="container">
                  <div class="header">
                    <h2>Password Reset Request</h2>
                  </div>
                  <div class="content">
                    <p>Hello,</p>
                    <p>We received a request to reset your password for the Harvest Call Ministries staff portal.</p>
                    <p>Click the button below to reset your password:</p>
                    <p><a href="${resetLink}" class="btn">Reset Password</a></p>
                    <p>This link will expire in 1 hour. If you didn't request this, please ignore this email.</p>
                  </div>
                  <div class="footer">
                    <p>Harvest Call Ministries &copy; ${new Date().getFullYear()}</p>
                  </div>
                </div>
              </body>
              </html>
            `
          });
          logger.info(`📧 Password reset email sent to ${normalizedEmail}`);
        } else {
          logger.info(`Password reset link for ${normalizedEmail}: ${resetLink}`);
        }
      }
      
      // Always show success message regardless of account existence
      res.send(`
        <html>
        <head>
          <title>Reset Request Sent</title>
          <style>
            body { 
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: #f8f9fa; 
              padding: 40px;
              text-align: center;
            }
            .card {
              background: white;
              max-width: 500px;
              margin: 0 auto;
              padding: 30px;
              border-radius: 10px;
              box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            }
            h2 { color: #2E7D32; }
            p { color: #333; line-height: 1.6; }
            .btn {
              display: inline-block;
              margin-top: 20px;
              padding: 12px 24px;
              background: #003366;
              color: white;
              text-decoration: none;
              border-radius: 6px;
              font-weight: 500;
            }
            .info {
              background: #e8f5e9;
              padding: 15px;
              border-radius: 8px;
              margin: 20px 0;
              border-left: 4px solid #2E7D32;
            }
          </style>
        </head>
        <body>
          <div class="card">
            <h2>Reset Request Received</h2>
            <div class="info">
              <p>If an account exists for <strong>${escapeHtml(email)}</strong>, 
              you'll receive password reset instructions shortly.</p>
            </div>
            <p>Please check your email and follow the link to set a new password.</p>
            <a href="/login" class="btn">Return to Login</a>
          </div>
        </body>
        </html>
      `);
    } catch (err) {
      logger.error('Password reset request error:', err);
      next(new DatabaseError('Failed to process password reset request'));
    }
  }
);

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

// Password reset handler
app.post('/reset-password', async (req, res, next) => {
  const { token, newPassword, confirmPassword } = req.body;
  
  // Validate input
  if (!token || !newPassword || !confirmPassword) {
    return res.status(400).json({
      error: {
        name: 'ValidationError',
        message: 'All fields are required'
      }
    });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({
      error: {
        name: 'ValidationError',
        message: 'Passwords do not match'
      }
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const accountId = decoded.id;

    // Hash new password asynchronously
    const newHash = await new Promise((resolve, reject) => {
      bcrypt.hash(newPassword, BCRYPT_COST, (err, hash) => {
        if (err) reject(new DatabaseError('Password hashing failed'));
        resolve(hash);
      });
    });

    // Update password
    await db('staff_accounts')
      .where('id', accountId)
      .update({ 
        password_hash: newHash,
        updated_at: new Date().toISOString()
      });

    // Send success response
    res.send(`
      <html>
      <head>
        <title>Password Updated</title>
        <style>
          body { font-family: Arial; padding: 40px; background: #f5f5f5; text-align: center; }
          .card { background: white; padding: 30px; max-width: 500px; margin: 0 auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h2 { color: #2E7D32; }
          .btn { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #003366; color: white; text-decoration: none; border-radius: 6px; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Password Updated Successfully!</h2>
          <p>Your password has been reset. You can now login with your new password.</p>
          <a href="/login" class="btn">Login Now</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(400).send(`
        <div style="text-align:center; padding:40px;">
          <h2 style="color:#d32f2f;">Invalid or Expired Token</h2>
          <p>The password reset link is invalid or has expired.</p>
          <p>Please request a new <a href="/forgot-password">password reset</a>.</p>
        </div>
      `);
    }
    logger.error('Password reset error:', err);
    next(err);
  }
});


// 1. Create dedicated staff authentication middleware
const requireStaffAuth = (req, res, next) => {
  if (req.session?.staffId) {
    logger.info(`🔒 Staff authenticated: ${req.session.staffId}`);
    return next();
  }
  logger.warn('🚫 Staff access denied - no session found');
  res.redirect('/login');  // Added redirect to login page
};

// Project Access Middleware
const checkProjectAccess = async (req, res, next) => {
  try {
    const staffId = req.session.staffId;
    const projectId = req.query.projectId;

    // Validate session
    if (!staffId) {
      return res.status(401).send('Authentication required');
    }
     // Validate project ID
    if (!projectId) {
      return res.status(400).send('Project ID is required');
    }

    // Convert to number and validate
    const numericProjectId = parseInt(projectId);
    if (isNaN(numericProjectId)) {
      return res.status(400).send('Invalid Project ID');
    }

    // Check database assignment
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

    // Attach project ID to request for later use
    req.projectId = numericProjectId;
    next();
  } catch (err) {
  next(new AppError('Server error during authorization', 500));
}
};

// 2. Updated staff dashboard route
app.get('/staff-dashboard', requireStaffAuth, async (req, res) => {
  try {
    // Get staffId from session instead of query parameter
    const staffId = req.session.staffId;
    const monthParam = req.query.month;

    // Validate staff exists
    const staff = await db('staff').where('id', staffId).first();
    if (!staff) {
      logger.error(`❌ Staff not found: ${staffId}`);
      return res.status(404).send('Staff not found');
    }

    // Date handling
// Replace in /staff-dashboard route:
const today = new Date();
const current = monthParam
  ? new Date(`${monthParam}-01T00:00:00.000Z`)
  : new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1));
const monthKey = current.toLocaleString('default', { 
  year: 'numeric', 
  month: 'long',
  timeZone: 'UTC'
});

    
    // Calculate date range
    const monthStart = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth(), 1));
const monthEnd = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() + 1, 0, 23, 59, 59, 999));

    // Get donations
    // ✅ Solution: Push filtering to the database
const donations = await db('donations')
  .where('metadata->>staffId', staffId.toString())  // Direct DB filter
  .whereBetween('created_at', [monthStart, monthEnd])
  .orderBy('created_at', 'desc');

    // Filter donations
    const filtered = donations.filter(d => {
  try {
    const rawDate = d.created_at || d.timestamp;
    if (!rawDate) return false;

    const parsedDate = new Date(rawDate);
    if (!(parsedDate >= monthStart && parsedDate <= monthEnd)) return false;

    function safeParseMetadata(metadata) {
  try {
    const parsed = typeof metadata === 'string' 
      ? JSON.parse(metadata) 
      : metadata;
    return metadataSchema.validate(parsed).value || {};
  } catch (e) {
    return {};
  }
}

    return metadata.staffId == staffId;
  } catch (err) {
    logger.error('❌ Bad donation entry:', d);
    return false;
  }
});


    // Calculate totals
    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 
      ? (totalAmount / donorCount).toFixed(2) 
      : 0;

    // Month navigation helpers
    const formatMonth = date => `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
    const prev = formatMonth(new Date(current.getFullYear(), current.getMonth() - 1, 1));
    const next = formatMonth(new Date(current.getFullYear(), current.getMonth() + 1, 1));

    
    // Generate beautiful HTML dashboard
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(staff.name)} - Staff Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #003366;
            --secondary: #2E7D32;
            --accent: #E67E22;
            --light-bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #333333;
            --text-light: #6c757d;
            --border: #e0e0e0;
            --success: #28a745;
            --info: #17a2b8;
            --shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: var(--light-bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }
        
        .dashboard-container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .staff-header {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .staff-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 36px;
            font-weight: 600;
        }
        
        .staff-info h1 {
            color: var(--primary);
            font-size: 28px;
            margin-bottom: 5px;
        }
        
        .staff-info p {
            color: var(--text-light);
            font-size: 16px;
        }
        
        .controls {
            display: flex;
            gap: 15px;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 15px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .btn:hover {
            background: #002244;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        /* Project selector styles */
        .project-selector {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }
        
        .project-selector h3 {
            color: var(--primary);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .project-selector select {
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid var(--border);
            font-size: 16px;
            background: white;
            transition: border-color 0.3s;
        }
        
        .project-selector select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(230, 126, 34, 0.2);
        }
        
        .month-nav {
            display: flex;
            align-items: center;
            gap: 15px;
            background: var(--card-bg);
            border-radius: 10px;
            padding: 15px 20px;
            box-shadow: var(--shadow);
            margin-bottom: 30px;
        }
        
        .nav-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--light-bg);
            color: var(--primary);
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 18px;
            text-decoration: none;
        }
        
        .nav-btn:hover {
            background: var(--primary);
            color: white;
            transform: translateY(-2px);
        }
        
        .current-month {
            font-size: 24px;
            font-weight: 600;
            color: var(--primary);
            flex-grow: 1;
            text-align: center;
        }
        
        .kpi-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .kpi-card {
            background: var(--card-bg);
            border-radius: 15px;
            padding: 25px;
            box-shadow: var(--shadow);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .kpi-card:hover {
            transform: translateY(-5px);
        }
        
        .kpi-icon {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
            font-size: 24px;
        }
        
        .total .kpi-icon {
            background: rgba(40, 167, 69, 0.15);
            color: var(--success);
        }
        
        .donations-count .kpi-icon {
            background: rgba(231, 126, 34, 0.15);
            color: var(--accent);
        }
        
        .donors .kpi-icon {
            background: rgba(23, 162, 184, 0.15);
            color: var(--info);
        }
        
        .avg-gift .kpi-icon {
            background: rgba(0, 51, 102, 0.15);
            color: var(--primary);
        }
        
        .kpi-card h3 {
            font-size: 16px;
            color: var(--text-light);
            margin-bottom: 10px;
        }
        
        .kpi-card .value {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .kpi-card .sub-value {
            font-size: 16px;
            color: var(--text-light);
        }
        
        .donations-table {
            background: var(--card-bg);
            border-radius: 15px;
            overflow: hidden;
            box-shadow: var(--shadow);
            margin-bottom: 30px;
        }
        
        .table-header {
            padding: 20px 25px;
            border-bottom: 1px solid var(--border);
        }
        
        .table-header h2 {
            color: var(--primary);
            font-size: 22px;
            font-weight: 600;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #f8fafc;
        }
        
        th {
            padding: 15px 25px;
            text-align: left;
            color: var(--text-light);
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tbody tr {
            border-bottom: 1px solid var(--border);
            transition: background 0.2s ease;
        }
        
        tbody tr:last-child {
            border-bottom: none;
        }
        
        tbody tr:hover {
            background: #f8fafc;
        }
        
        td {
            padding: 15px 25px;
            font-size: 16px;
        }
        
        .donor-name {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .donor-icon {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(0, 51, 102, 0.1);
            color: var(--primary);
            font-size: 18px;
        }
        
        .amount {
            font-weight: 600;
            color: var(--primary);
        }
        
        .type {
            font-size: 14px;
            padding: 4px 10px;
            border-radius: 20px;
            background: #e8f5e9;
            color: #2E7D32;
            display: inline-block;
        }
        
        .type.one-time {
            background: #e3f2fd;
            color: #1565c0;
        }
        
        .reference {
            font-family: monospace;
            font-size: 14px;
            color: var(--text-light);
        }
        
        .no-donations {
            text-align: center;
            padding: 40px;
            color: var(--text-light);
        }
        
        .no-donations i {
            font-size: 48px;
            color: #e0e0e0;
            margin-bottom: 20px;
        }
        
        .no-donations h3 {
            font-size: 24px;
            margin-bottom: 10px;
            color: var(--text);
        }
        
        .no-donations p {
            max-width: 500px;
            margin: 0 auto;
        }
        
        .footer {
            text-align: center;
            color: var(--text-light);
            font-size: 14px;
            padding: 20px;
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                align-items: flex-start;
                gap: 20px;
            }
            
            .staff-header {
                flex-direction: column;
                text-align: center;
                gap: 15px;
            }
            
            .controls {
                width: 100%;
                justify-content: center;
            }
            
            .month-nav {
                flex-wrap: wrap;
            }
            
            .kpi-cards {
                grid-template-columns: 1fr;
            }
            
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="header">
            <div class="staff-header">
                <div class="staff-avatar">${staff.name.charAt(0)}</div>
                <div class="staff-info">
                    <h1>${escapeHtml(staff.name)}</h1>
                    <p>Staff Support Dashboard</p>
                </div>
            </div>
            <div class="controls">
                <a href="/" class="btn">
                    <i class="fas fa-home"></i> Main Dashboard
                </a>
            </div>
        </div>
        
        <!-- Project Selector Section -->
        <div class="project-selector">
            <h3><i class="fas fa-project-diagram"></i> View Project Dashboard</h3>
            <select id="project-select">
                <option value="">Loading projects...</option>
            </select>
        </div>
        
        <div class="month-nav">
            <a href="/staff-dashboard?month=${prev}" class="nav-btn">
                <i class="fas fa-chevron-left"></i>
            </a>
            <div class="current-month">${escapeHtml(monthKey)}</div>
            <a href="/staff-dashboard?month=${next}" class="nav-btn">
                <i class="fas fa-chevron-right"></i>
            </a>
        </div>
        
        <div class="kpi-cards">
            <div class="kpi-card total">
                <div class="kpi-icon">
                    <i class="fas fa-donate"></i>
                </div>
                <h3>Total Support</h3>
                <div class="value">₦${totalAmount.toLocaleString()}</div>
                <div class="sub-value">Amount Raised</div>
            </div>
            
            <div class="kpi-card donations-count">
                <div class="kpi-icon">
                    <i class="fas fa-hand-holding-heart"></i>
                </div>
                <h3>Donations</h3>
                <div class="value">${filtered.length}</div>
                <div class="sub-value">Received This Month</div>
            </div>
            
            <div class="kpi-card donors">
                <div class="kpi-icon">
                    <i class="fas fa-users"></i>
                </div>
                <h3>Supporters</h3>
                <div class="value">${donorCount}</div>
                <div class="sub-value">Individual Donors</div>
            </div>
            
            <div class="kpi-card avg-gift">
                <div class="kpi-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <h3>Average Gift</h3>
                <div class="value">₦${avgDonation}</div>
                <div class="sub-value">Per Supporter</div>
            </div>
        </div>
        
        <div class="donations-table">
            <div class="table-header">
                <h2><i class="fas fa-list"></i> Donation Details</h2>
            </div>
            
            ${
                filtered.length === 0 
                    ? `<div class="no-donations">
                        <i class="fas fa-inbox"></i>
                        <h3>No Donations This Month</h3>
                        <p>Your supporters haven't made any contributions for ${escapeHtml(monthKey)} yet. Share your ministry story to encourage giving!</p>
                    </div>`
                    : `<table>
                        <thead>
                            <tr>
                                <th>Supporter</th>
                                <th>Amount</th>
                                <th>Type</th>
                                <th>Reference</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered.map(d => {
  // ✅ Safely parse metadata
  let metadata = {};
  try {
    metadata = typeof d.metadata === 'string' 
      ? JSON.parse(d.metadata) 
      : d.metadata || {};
  } catch (err) {
    logger.error('❌ Metadata parse error for donation ID', d.id);
  }

  // ✅ Safe and formatted date
 // Consistent UTC handling
const monthStart = new Date(Date.UTC(year, month - 1, 1));
const monthEnd = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));

// Proper UTC formatting
const formattedDate = new Date(rawDate).toLocaleDateString('en-US', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'short',
  day: 'numeric'
});

// Correct month navigation
function getPrevMonth(date) {
  const d = new Date(date);
  d.setUTCMonth(d.getUTCMonth() - 1);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}
  

  // Continue with rendering...

                                return `<tr>
                                    <td>
                                        <div class="donor-name">
                                            <div class="donor-icon">
                                                <i class="fas fa-user"></i>
                                            </div>
                                            <div>${escapeHtml(metadata.donorName || 'Anonymous Supporter')}</div>
                                        </div>
                                    </td>
                                    <td class="amount">₦${(d.amount / 100).toLocaleString()}</td>
                                    <td>${escapeHtml(metadata.donationType || 'one-time')}</td>
                                    <td class="reference">${escapeHtml(d.reference)}</td>
                                    <td>${donationDate.toLocaleDateString('en-US', { timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric' })}</td>
                                </tr>`;
                            }).join('')}
                        </tbody>
                    </table>`
            }
        </div>
        
        <div class="footer">
           <p>Harvest Call Ministries • Generated on ${escapeHtml(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }))}</p>
        </div>
    </div>
    
    <script>
        // Project Dashboard Navigation
        function viewProjectDashboard(projectId) {
            if (projectId) {
                window.location.href = '/project-dashboard?projectId=' + projectId;
            }
        }
        
        // Load accessible projects
        async function loadProjects() {
            try {
                const response = await fetch('/api/accessible-projects');
                
                if (!response.ok) {
                    throw new Error('Failed to load projects');
                }
                
                const projects = await response.json();
                const select = document.getElementById('project-select');
                
                // Build options using string concatenation
                let optionsHTML = '<option value="">-- Select Project --</option>';
                projects.forEach(project => {
                    optionsHTML += '<option value="' + project.id + '">' + project.name + '</option>';
                });
                
                select.innerHTML = optionsHTML;
                
                // Add change event listener
                select.addEventListener('change', function() {
                    viewProjectDashboard(this.value);
                });
                
            } catch (error) {
                logger.error('Project load error:', error);
                const select = document.getElementById('project-select');
                select.innerHTML = '<option value="">Failed to load projects</option>';
            }
        }
        
        // Navigation loading indicator
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                // Show loading indicator
                document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;"><div style="animation: spin 1s linear infinite; width: 60px; height: 60px; border-radius: 50%; background: #e0e0e0; display: flex; align-items: center; justify-content: center;"><i class="fas fa-spinner" style="font-size: 30px; color: #003366;"></i></div><style>@keyframes spin {100% {transform: rotate(360deg);}}</style></div>';
            });
        });
        
        // Load projects when page is ready
        document.addEventListener('DOMContentLoaded', loadProjects);
    </script>
</body>
</html>
`;
    res.send(html);
  } catch (err) {
  next(new AppError('Failed to load staff dashboard', 500));
}
});


// Project-Specific Dashboard
app.get('/project-dashboard', 
  requireStaffAuth,    // First check staff is logged in 
  checkProjectAccess,  // Then check project permission
  async (req, res, next) => {
  try {
    const projectId = req.projectId;
    const monthParam = req.query.month;

    if (!projectId) {
      return res.status(400).send('Missing projectId');
    }

    const project = await db('projects').where('id', parseInt(projectId)).first();
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
    function safeParseMetadata(metadata) {
  try {
    const parsed = typeof metadata === 'string' 
      ? JSON.parse(metadata) 
      : metadata;
    return metadataSchema.validate(parsed).value || {};
  } catch (e) {
    return {};
  }
}

    // Coerce both sides to string for safe comparison
    return String(metadata.projectId) === String(projectId);
  } catch (err) {
    logger.error('❌ Bad metadata in donation ID', d.id, ':', d.metadata);
    return false;
  }
});


    // Calculate totals
    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 ? (totalAmount / donorCount).toFixed(2) : 0;

    // Month navigation helpers
    const prevMonthDate = new Date(current);
prevMonthDate.setUTCMonth(prevMonthDate.getUTCMonth() - 1);
const prev = `${prevMonthDate.getUTCFullYear()}-${String(prevMonthDate.getUTCMonth() + 1).padStart(2, '0')}`;

    function nextMonth(date) {
      const d = new Date(date.getFullYear(), date.getMonth() + 1, 1);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    }

    // Generate beautiful HTML dashboard
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${escapeHtml(project.name)} - Project Dashboard</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #003366;
                --secondary: #2E7D32;
                --accent: #E67E22;
                --light-bg: #f8f9fa;
                --card-bg: #ffffff;
                --text: #333333;
                --text-light: #6c757d;
                --border: #e0e0e0;
                --success: #28a745;
                --info: #17a2b8;
                --shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                background-color: var(--light-bg);
                color: var(--text);
                line-height: 1.6;
                padding: 20px;
            }
            
            .dashboard-container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 1px solid var(--border);
            }
            
            .project-header {
                display: flex;
                align-items: center;
                gap: 20px;
            }
            
            .project-icon {
                width: 80px;
                height: 80px;
                border-radius: 50%;
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 36px;
            }
            
            .project-info h1 {
                color: var(--primary);
                font-size: 28px;
                margin-bottom: 10px;
            }
            
            .project-info p {
                color: var(--text-light);
                font-size: 16px;
                max-width: 600px;
            }
            
            .controls {
                display: flex;
                gap: 15px;
            }
            
            .btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 10px 15px;
                background: var(--primary);
                color: white;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 500;
                transition: all 0.3s;
            }
            
            .btn:hover {
                background: #002244;
                transform: translateY(-2px);
                box-shadow: var(--shadow);
            }
            
            .month-nav {
                display: flex;
                align-items: center;
                gap: 15px;
                background: var(--card-bg);
                border-radius: 10px;
                padding: 15px 20px;
                box-shadow: var(--shadow);
                margin-bottom: 30px;
            }
            
            .nav-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: var(--light-bg);
                color: var(--primary);
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 18px;
                text-decoration: none;
            }
            
            .nav-btn:hover {
                background: var(--primary);
                color: white;
                transform: translateY(-2px);
            }
            
            .current-month {
                font-size: 24px;
                font-weight: 600;
                color: var(--primary);
                flex-grow: 1;
                text-align: center;
            }
            
            .kpi-cards {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .kpi-card {
                background: var(--card-bg);
                border-radius: 15px;
                padding: 25px;
                box-shadow: var(--shadow);
                text-align: center;
                transition: transform 0.3s ease;
            }
            
            .kpi-card:hover {
                transform: translateY(-5px);
            }
            
            .kpi-icon {
                width: 60px;
                height: 60px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 15px;
                font-size: 24px;
            }
            
            .total .kpi-icon {
                background: rgba(40, 167, 69, 0.15);
                color: var(--success);
            }
            
            .donations-count .kpi-icon {
                background: rgba(231, 126, 34, 0.15);
                color: var(--accent);
            }
            
            .donors .kpi-icon {
                background: rgba(23, 162, 184, 0.15);
                color: var(--info);
            }
            
            .avg-gift .kpi-icon {
                background: rgba(0, 51, 102, 0.15);
                color: var(--primary);
            }
            
            .kpi-card h3 {
                font-size: 16px;
                color: var(--text-light);
                margin-bottom: 10px;
            }
            
            .kpi-card .value {
                font-size: 32px;
                font-weight: 700;
                margin-bottom: 5px;
            }
            
            .kpi-card .sub-value {
                font-size: 16px;
                color: var(--text-light);
            }
            
            .donations-table {
                background: var(--card-bg);
                border-radius: 15px;
                overflow: hidden;
                box-shadow: var(--shadow);
                margin-bottom: 30px;
            }
            
            .table-header {
                padding: 20px 25px;
                border-bottom: 1px solid var(--border);
            }
            
            .table-header h2 {
                color: var(--primary);
                font-size: 22px;
                font-weight: 600;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
            }
            
            thead {
                background: #f8fafc;
            }
            
            th {
                padding: 15px 25px;
                text-align: left;
                color: var(--text-light);
                font-weight: 600;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            tbody tr {
                border-bottom: 1px solid var(--border);
                transition: background 0.2s ease;
            }
            
            tbody tr:last-child {
                border-bottom: none;
            }
            
            tbody tr:hover {
                background: #f8fafc;
            }
            
            td {
                padding: 15px 25px;
                font-size: 16px;
            }
            
            .donor-name {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .donor-icon {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(0, 51, 102, 0.1);
                color: var(--primary);
                font-size: 18px;
            }
            
            .amount {
                font-weight: 600;
                color: var(--primary);
            }
            
            .type {
                font-size: 14px;
                padding: 4px 10px;
                border-radius: 20px;
                background: #e8f5e9;
                color: #2E7D32;
                display: inline-block;
            }
            
            .type.one-time {
                background: #e3f2fd;
                color: #1565c0;
            }
            
            .reference {
                font-family: monospace;
                font-size: 14px;
                color: var(--text-light);
            }
            
            .no-donations {
                text-align: center;
                padding: 40px;
                color: var(--text-light);
            }
            
            .no-donations i {
                font-size: 48px;
                color: #e0e0e0;
                margin-bottom: 20px;
            }
            
            .no-donations h3 {
                font-size: 24px;
                margin-bottom: 10px;
                color: var(--text);
            }
            
            .no-donations p {
                max-width: 500px;
                margin: 0 auto;
            }
            
            .progress-container {
                background: var(--light-bg);
                border-radius: 12px;
                height: 20px;
                margin: 20px 0;
                overflow: hidden;
            }
            
            .progress-bar {
                height: 100%;
                background: linear-gradient(90deg, var(--primary), var(--secondary));
                border-radius: 12px;
                transition: width 0.5s ease;
            }
            
            .funding-goal {
                display: flex;
                justify-content: space-between;
                margin-top: 5px;
                font-size: 14px;
                color: var(--text-light);
            }
            
            .footer {
                text-align: center;
                color: var(--text-light);
                font-size: 14px;
                padding: 20px;
            }
            
            @media (max-width: 768px) {
                .header {
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 20px;
                }
                
                .project-header {
                    flex-direction: column;
                    text-align: center;
                    gap: 15px;
                }
                
                .controls {
                    width: 100%;
                    justify-content: center;
                }
                
                .month-nav {
                    flex-wrap: wrap;
                }
                
                .kpi-cards {
                    grid-template-columns: 1fr;
                }
                
                table {
                    display: block;
                    overflow-x: auto;
                }
            }
        </style>
    </head>
    <body>
        <div class="dashboard-container">
            <div class="header">
                <div class="project-header">
                    <div class="project-icon">
                        <i class="fas fa-project-diagram"></i>
                    </div>
                    <div class="project-info">
                        <h1>${escapeHtml(project.name)}</h1>
                        <p>${escapeHtml(project.description || 'Project funding dashboard')}</p>
                    </div>
                </div>
                <div class="controls">
                    <a href="/" class="btn">
                        <i class="fas fa-home"></i> Main Dashboard
                    </a>
                </div>
            </div>
            
            <div class="month-nav">
                <a href="/project-dashboard?projectId=${projectId}&month=${prevMonth(current)}" class="nav-btn">
                    <i class="fas fa-chevron-left"></i>
                </a>
                <div class="current-month">${escapeHtml(monthKey)}</div>
                <a href="/project-dashboard?projectId=${projectId}&month=${nextMonth(current)}" class="nav-btn">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </div>
            
            <div class="kpi-cards">
                <div class="kpi-card total">
                    <div class="kpi-icon">
                        <i class="fas fa-donate"></i>
                    </div>
                    <h3>Total Funding</h3>
                    <div class="value">₦${totalAmount.toLocaleString()}</div>
                    <div class="sub-value">Amount Raised</div>
                </div>
                
                <div class="kpi-card donations-count">
                    <div class="kpi-icon">
                        <i class="fas fa-hand-holding-heart"></i>
                    </div>
                    <h3>Donations</h3>
                    <div class="value">${filtered.length}</div>
                    <div class="sub-value">Received This Month</div>
                </div>
                
                <div class="kpi-card donors">
                    <div class="kpi-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <h3>Supporters</h3>
                    <div class="value">${donorCount}</div>
                    <div class="sub-value">Individual Donors</div>
                </div>
                
                <div class="kpi-card avg-gift">
                    <div class="kpi-icon">
                        <i class="fas fa-chart-line"></i>
                    </div>
                    <h3>Average Gift</h3>
                    <div class="value">₦${avgDonation}</div>
                    <div class="sub-value">Per Supporter</div>
                </div>
            </div>
            
            <div class="donations-table">
                <div class="table-header">
                    <h2><i class="fas fa-list"></i> Donation Details</h2>
                </div>
                
                ${filtered.length === 0 ? `
                    <div class="no-donations">
                        <i class="fas fa-inbox"></i>
                        <h3>No Donations This Month</h3>
                        <p>This project hasn't received any contributions for ${escapeHtml(monthKey)} yet. Share the impact to encourage support!</p>
                    </div>
                ` : `
                    <table>
                        <thead>
                            <tr>
                                <th>Supporter</th>
                                <th>Amount</th>
                                <th>Type</th>
                                <th>Reference</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered.map(d => {
  let metadata = {};
  try {
    metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
  } catch (err) {
    logger.error('❌ Metadata parse error for donation:', d.id);
  }

  c// Consistent UTC handling
const monthStart = new Date(Date.UTC(year, month - 1, 1));
const monthEnd = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));

// Proper UTC formatting
const formattedDate = new Date(rawDate).toLocaleDateString('en-US', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'short',
  day: 'numeric'
});

// Correct month navigation
function getPrevMonth(date) {
  const d = new Date(date);
  d.setUTCMonth(d.getUTCMonth() - 1);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}
                                return `
                                <tr>
                                    <td>
                                        <div class="donor-name">
                                            <div class="donor-icon">
                                                <i class="fas fa-user"></i>
                                            </div>
                                            <div>${escapeHtml(metadata.donorName || 'Anonymous Supporter')}</div>
                                        </div>
                                    </td>
                                    <td class="amount">₦${(d.amount / 100).toLocaleString()}</td>
                                    <td>${escapeHtml(metadata.donationType || 'one-time')}</td>
                                    <td class="reference">${escapeHtml(d.reference)}</td>
                                    <td>${displayDate}</td>
                                </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                `}
            </div>
            
            <div class="footer">
                <p>Harvest Call Ministries • Generated on ${escapeHtml(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }))}</p>
            </div>
        </div>
        
        <script>
            // Add loading indicator during navigation
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.addEventListener('click', function(e) {
                    // Show loading indicator
                    document.body.innerHTML = '<div style="display:flex;justify-content:center;align-items:center;height:100vh;"><div style="animation: spin 1s linear infinite; width: 60px; height: 60px; border-radius: 50%; background: #e0e0e0; display: flex; align-items: center; justify-content: center;"><i class="fas fa-spinner" style="font-size: 30px; color: #003366;"></i></div><style>@keyframes spin {100% {transform: rotate(360deg);}}</style></div>';
                });
            });
        </script>
    </body>
    </html>
    `;

    res.send(html);
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

// ✅ Global error handler
app.use((err, req, res, next) => {
  // Handle rate limiter proxy error specifically
  if (err.code === 'ERR_ERL_UNEXPECTED_X_FORWARDED_FOR') {
    return res.status(500).json({
      error: {
        name: 'ProxyError',
        message: 'Proxy configuration error',
        details: 'Server is behind a proxy but not configured to trust it'
      }
    });
  }
  
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
  
  logger.error('❌ Uncaught error:', err);
  res.status(status).json(response);
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
