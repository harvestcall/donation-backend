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
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');


const app = express();
app.set('trust proxy', true);  // Trust Render.com proxies
logger.info('NODE_ENV:', process.env.NODE_ENV);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ✅ CORS Configuration - Added per security recommendation
app.use(cors({ 
  origin: process.env.FRONTEND_URL || process.env.FRONTEND_BASE_URL,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('hex');

  // ✅ Helmet is now applied *after* nonce is set, and per request
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: [
          "'self'",
          `'nonce-${res.locals.cspNonce}'`,
          "https://cdnjs.cloudflare.com",
          "https://fonts.googleapis.com"
        ],
        scriptSrc: [
          "'self'",
          `'nonce-${res.locals.cspNonce}'`,
          "https://cdnjs.cloudflare.com"
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", process.env.PAYSTACK_API_URL || "https://api.paystack.co"]
      }
    },
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: 'same-origin' }
  })(req, res, next); // <-- Important: apply helmet immediately
});


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

// Serve static files from "public" directory
app.use(express.static(path.join(__dirname, 'public')));


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

app.use(cookieParser());         // MUST come before CSRF
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


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

const isProduction = process.env.NODE_ENV === 'production';

// 🧠 CSRF middleware setup
const {
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  cookieName: "__Host-hc-csrf-token",
  cookieOptions: {
    sameSite: "strict",
    path: "/",               // ✅ Required for __Host- prefix
    secure: isProduction,    // ✅ Conditionally secure
    httpOnly: true,
  },
  size: 64,
  ignoredMethods: ["GET", "HEAD", "OPTIONS"]
});

// ✅ Middleware order matters!

app.use(doubleCsrfProtection);   // CSRF for all POSTs

// ✅ Attach CSRF token to templates
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken?.() || '';
  next();
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
  res.render('donation-form', {
    cspNonce: res.locals.cspNonce
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


// Force CSRF token generation
const ensureCsrfToken = (req, res, next) => {
  res.locals.csrfToken = req.csrfToken?.() || '';
  next();
};

// ✅ Login form route (GET)
app.get('/login', (req, res) => {
  res.render('login', {
    csrfToken: req.csrfToken?.() || '',
    cspNonce: res.locals.cspNonce,
    error: req.query.error
  });
});



// Login Handler
app.post('/login',
  doubleCsrfProtection,
  (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
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

      req.session.regenerate(err => {
        if (err) return next(new AppError('Login failed. Please try again.', 500));
        req.session.staffId = account.staff_id;
        req.session.accountId = account.id;
        return res.redirect(303, '/staff-dashboard');
      });
    } catch (err) {
      if (err === invalidCsrfTokenError) return next(err);
      next(new DatabaseError('Server error during login.'));
    }
  }
);




// Password reset request endpoint
app.get('/forgot-password', (req, res) => {
  const csrfToken = res.locals.csrfToken;
  const cspNonce = res.locals.cspNonce;
  res.render('forgot-password', { csrfToken, cspNonce });
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

// 🔐 Staff Authentication Middleware
const requireStaffAuth = (req, res, next) => {
  if (req.session && req.session.staffId) {
    return next();
  }
  res.redirect('/login');
};


// Password reset handler
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
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    console.warn("⚠️ Invalid CSRF token");
    return res.redirect('/login?error=Invalid%20CSRF%20token.%20Please%20try%20again.');
  }

  if (err instanceof DatabaseError) {
    return res.status(500).render('error', { message: 'Database error' });
  }

  next(err);
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
