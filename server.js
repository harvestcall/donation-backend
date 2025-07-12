// ✅ Load environment variables
require('dotenv').config();

// ✅ Core dependencies
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
const rateLimit = require('express-rate-limit');
const formatCurrency = require('./utils/formatCurrency');
const logger = require('./utils/logger');
const { notifyAdmin } = require('./utils/alerts');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = require('dompurify')(window);
const validator = require('validator');
const { escapeHtml } = require('./utils/helpers');
const { body, validationResult } = require('express-validator');


// ✅ PostgreSQL pool
const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const isProduction = process.env.NODE_ENV === 'production'; // For secure settings

// ✅ Custom error classes
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
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

// ✅ Double Csrf Options
const { doubleCsrf } = require('csrf-csrf');
const { csrfCookieName, options } = require('./config/csrf-config');


const finalOptions = {
  ...options,
  getSecret: (req) => {
    if (!req.session.csrfSecret) {
      req.session.csrfSecret = crypto.randomBytes(64).toString('hex');
    }
    return req.session.csrfSecret;
  },
  cookieOptions: {
    httpOnly: false,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 1000 * 60 * 15 // 15 minutes
  }
};

const { doubleCsrfProtection, generateToken } = doubleCsrf(finalOptions);

// ✅ Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', true); // Trust Render.com proxies
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ✅ Generate CSP nonce per request
app.use((req, res, next) => {
  res.locals.cspNonce = Buffer.from(crypto.randomBytes(16)).toString('base64');
  next();
});

// ✅ Session middleware - MUST come before CSRF
// Determine secure cookie options based on environment
const sessionCookieOptions = {
  path: '/',
  httpOnly: true,
  secure: isProduction, // Only send over HTTPS in production
  sameSite: isProduction ? 'lax' : 'strict', // lax for general use, strict for sensitive actions
  maxAge: 30 * 60 * 1000 // 30 minutes - reduce risk of session hijacking
};

if (!isProduction) {
  sessionCookieOptions.secure = false; // Allow HTTP in development
}

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
  cookie: sessionCookieOptions
}));

// ✅ Apply CSP headers after session middleware
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

// ✅ CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || process.env.FRONTEND_BASE_URL,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true
}));

// ✅ Static files + body parsers
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(cookieParser());

// ✅ Apply doubleCsrfProtection after session and CSP
app.use(doubleCsrfProtection);

// ✅ Ensure CSRF token is available in locals
app.use((req, res, next) => {
  try {
    if (req.sessionID) {
      const token = generateToken(req, res);
      res.locals.csrfToken = token;
      res.cookie(csrfCookieName, token, {
        httpOnly: false,
        sameSite: 'lax',
        secure: isProduction,
        path: '/',
        maxAge: 1000 * 60 * 15
      });
    }
    next();
  } catch (err) {
    logger.error('CSRF token error:', err.message);
    next(new AppError('CSRF token generation failed', 500));
  }
});

// ✅ Environment validation
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
  message: 'Too many payment requests from this IP'
});

const webhookLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100,
  message: 'Too many webhook requests'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many login attempts'
});

// ✅ Paystack webhook verification
const verifyPaystackWebhook = (req, res, next) => {
  const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                     .update(req.rawBody)
                     .digest('hex');
  hash === req.headers['x-paystack-signature'] ? next() : res.status(401).send('Unauthorized');
};


const sanitizeHeader = str => typeof str === 'string'
  ? str.replace(/[\r\n]/g, '')
  : '';

// ✅ Database connection (Knex)
const db = require('./db');
logger.info(`🛠 Using DB: ${db.client.config.connection.host}`);
logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);

// ✅ Bcrypt configuration
const BCRYPT_COST = Math.min(Math.max(parseInt(process.env.BCRYPT_COST) || 8, 8), 12);
logger.info(`🔒 Bcrypt cost: ${BCRYPT_COST}`);

// ✅ Joi validation schema
const metadataSchema = Joi.object({
  staffId: Joi.string().optional(),
  projectId: Joi.string().optional(),
  donorName: Joi.string().optional(),
  donationType: Joi.string().valid('one-time', 'recurring').optional()
});

// ✅ Request validation helper
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
};

// ✅ Display name helper
async function getDisplayName(type, id, db) {
  const table = type === 'staff' ? 'staff' : 'projects';
  const result = await db(table).where('id', parseInt(id)).first();
  return result ? result.name : null;
}

// ✅ Auth middleware
const requireAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Basic ')) {
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

// Sanitize and escape strings for safe HTML display
function sanitizeHtml(input) {
  return DOMPurify.sanitize(validator.escape(input || ''));
}

// Sanitize and trim strings for general text inputs
function sanitizeText(input) {
  return validator.trim(input || '');
}

// Sanitize and normalize emails
function sanitizeEmail(input) {
  return validator.normalizeEmail(input || '', { gmail_remove_dots: false });
}

// Process Version Check to Avoid Future Issues
if (process.versions.node.split('.')[0] < 18) {
  throw new Error('Node.js version must be 18 or higher');
}

// ===== ROUTES START HERE ===== //
app.get('/healthz', (req, res) => res.status(200).send('OK'));
app.get('/csrf-test', (req, res) => {
  res.send(`Your CSRF token is: ${res.locals.csrfToken}`);
});

// ✅ Database initialization
async function initializeDatabase() {
  try {
    await db.migrate.latest();
    logger.info('📦 Migrations completed');
    const staff = await db('staff').select('*');
    logger.info(`👥 Staff records: ${staff.length}`);
  } catch (err) {
    logger.error('❌ Database init error:', err.message);
    notifyAdmin(`Database initialization failed: ${err.message}`);
  }
}

// ✅ Start server
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    logger.info(`🚀 Server running on port ${PORT}`);
  });
});


// Root route - Donation Form
app.get('/', (req, res, next) => {
  logger.debug('[ROUTE /] Rendering donation-form EJS');
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


// ✅ Payment Initialization Route
app.post('/initialize-payment', [
  body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
  body('amount')
  .isFloat({ min: 0.5 }).withMessage('Amount must be at least ₦0.50')
  .toFloat(),
  body('currency').optional().isIn(['NGN', 'USD']).withMessage('Currency must be NGN or USD'),
  body('donationType').optional().isIn(['one-time', 'recurring']).withMessage('Invalid donation type'),
  body('purpose').optional().isIn(['general', 'staff', 'project']).withMessage('Invalid purpose selected'),
  body('name').optional().trim().escape().withMessage('Invalid name format')
], validateRequest, csrfLimiter, async (req, res) => {
  try {
    const { email, amount, currency = 'NGN', donationType = 'one-time', purpose = 'general' } = req.body;
    const donorName = req.body.name || 'Friend';

    // ✅ Prepare metadata
    const metadata = {};
    if (donorName) metadata.donorName = validator.escape(donorName.trim());
    metadata.donationType = donationType;
    metadata.purpose = purpose;

    const amountInKobo = Math.round(amount * 100); // Convert to kobo

    // ✅ Call Paystack API
    const response = await axios.post('https://api.paystack.co/transaction/initialize ', {
      email,
      amount: amountInKobo,
      currency,
      metadata,
      callback_url: `${process.env.FRONTEND_BASE_URL}/thank-you`
    }, {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const authorizationUrl = response.data.data.authorization_url;
    const reference = response.data.data.reference;

    // ✅ Log payment request
    logger.info(`💸 Payment initialized: ${reference} | Email: ${email} | Amount: ₦${amount}`);

    // ✅ Build thank-you URL with sanitized values
    const thankYouUrl = new URL(`${process.env.FRONTEND_BASE_URL}/thank-you`);
    thankYouUrl.searchParams.append('name', donorName);
    thankYouUrl.searchParams.append('amount', amount);
    thankYouUrl.searchParams.append('currency', currency);
    thankYouUrl.searchParams.append('type', donationType);
    thankYouUrl.searchParams.append('purpose', purpose);

    res.json({
      status: 'success',
      authorization_url: authorizationUrl,
      reference
    });

  } catch (error) {
    logger.error('❌ Error initializing payment:', error.message);
    logger.debug('Error details:', error.response?.data || 'No response data');

    return res.status(error.response?.status || 500).json({
      status: 'error',
      message: error.response?.data?.message || error.message || 'Payment initialization failed'
    });
  }
});


// ✅ Webhook Handler - Process Paystack webhook events
app.post('/webhook', webhookLimiter, verifyPaystackWebhook, async (req, res, next) => {
  try {
    const event = req.body;

    // ✅ Only handle successful charge events
    if (event.event !== 'charge.success') {
      logger.info(`🔔 Ignored webhook event: ${event.event}`);
      return res.status(200).send('Ignored');
    }

    const paymentData = event.data;

    // ✅ Validate amount
    if (!paymentData.amount || paymentData.amount <= 0) {
      logger.warn('❌ Invalid or zero donation amount:', paymentData.amount);
      return res.status(400).json({
        error: {
          name: 'ValidationError',
          message: 'Invalid donation amount'
        }
      });
    }

    // ✅ Sanitize email
    const sanitizedEmail = sanitizeEmail(paymentData.customer.email);

    // ✅ Parse metadata safely
    let safeMetadata = {};
    try {
      if (typeof paymentData.metadata === 'string') {
        safeMetadata = JSON.parse(paymentData.metadata);
      } else {
        safeMetadata = paymentData.metadata || {};
      }
    } catch (err) {
      logger.warn('⚠️ Failed to parse metadata:', err.message);
      safeMetadata = {};
    }

    // ✅ Insert into DB
    await db('donations').insert({
      email: sanitizedEmail,
      reference: paymentData.reference,
      amount: paymentData.amount,
      currency: paymentData.currency,
      meta: JSON.stringify(safeMetadata),
      created_at: new Date().toISOString()
    });


    // ✅ Log success
    const donorName = safeMetadata.donorName || 'Anonymous Supporter';
    logger.info(`✅ Verified Payment: ${paymentData.reference} | Donor: ${donorName}`);

    // ✅ Send thank-you email
    const formattedAmount = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: paymentData.currency
    }).format(paymentData.amount / 100);

    const purposeText = safeMetadata.purpose === 'staff' ? 'Staff Support' :
                        safeMetadata.purpose === 'project' ? 'Project Support' : 'General Ministry';

    if (process.env.SENDGRID_API_KEY) {
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);
      await sgMail.send({
        to: sanitizedEmail,
        from: { name: 'Harvest Call Ministries', email: 'giving@harvestcallafrica.org' },
        subject: `Thank You, ${donorName}! Your Donation Has Been Received`,
        html: `
          <html>
            <body style="font-family: Arial, sans-serif; background-color: #f8f9fa; padding: 20px;">
              <div style="background: white; border-left: 6px solid #003366; padding: 20px; max-width: 600px; margin: auto; border-radius: 8px;">
                <h2 style="color: #003366;">Thank You for Your Generosity</h2>
                <p>We're incredibly grateful for your support.</p>
                <p><strong>Donated:</strong> ${formattedAmount}</p>
                <p><strong>Purpose:</strong> ${purposeText}</p>
                <p>Your gift helps indigenous missionaries reach unreached communities across Africa.</p>
                <p style="margin-top: 20px;"><a href="https://harvestcallafrica.org " style="color: #003366;">Visit Our Website</a></p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
                <p style="font-size: 12px; color: #6c757d;">You're receiving this because you made a donation to Harvest Call Ministries.</p>
              </div>
            </body>
          </html>
        `
      });

      logger.info(`📧 Thank-you email sent to ${sanitizedEmail}`);
    }

    res.status(200).json({ status: 'success' });

  } catch (err) {
    logger.error('❌ Webhook handler error:', err.message);
    next(new AppError('Failed to process webhook.', 500));
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
          .distinct('email')
          .whereBetween('created_at', [monthStart, monthEnd])
      ]);

      const staffMap = new Map(allStaff.map(s => [s.id, s]));
      const projectMap = new Map(allProjects.map(p => [p.id, p]));

      const summary = {
        total: 0,
        totalStaff: 0,
        totalProject: 0,
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

      const donorCount = rawDonations.length;
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

      logger.info(`🔐 Admin summary accessed by IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);

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
      next(new DatabaseError('Failed to load admin summary'));
    }
  }
);

// Export Admin Summary
app.get('/admin/export/summary', requireAuth, async (req, res, next) => {
  const format = req.query.format || 'csv';
  const targetMonth = req.query.month || new Date().toISOString().slice(0, 7);
  const [year, month] = targetMonth.split('-').map(Number);
  const monthStart = new Date(Date.UTC(year, month - 1, 1));
  const monthEnd = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));

  const [allStaff, allProjects, aggregatedData] = await Promise.all([
    db('staff').select('id', 'name', 'active'),
    db('projects').select('id', 'name'),
    db('donations')
      .select(
        db.raw("CASE WHEN metadata->>'staffId' ~ '^\\d+$' THEN (metadata->>'staffId')::integer ELSE NULL END as staff_id"),
        db.raw("CASE WHEN metadata->>'projectId' ~ '^\\d+$' THEN (metadata->>'projectId')::integer ELSE NULL END as project_id"),
        db.raw('SUM(amount) as total_amount')
      )
      .whereBetween('created_at', [monthStart, monthEnd])
      .groupBy('staff_id', 'project_id')
  ]);

  const staffMap = new Map(allStaff.map(s => [s.id, s]));
  const projectMap = new Map(allProjects.map(p => [p.id, p]));

  const rows = [];

  for (const row of aggregatedData) {
    const amount = row.total_amount / 100;
    if (row.staff_id && staffMap.has(row.staff_id)) {
      const staff = staffMap.get(row.staff_id);
      rows.push([staff.name, 'Staff', amount]);
    } else if (row.project_id && projectMap.has(row.project_id)) {
      const project = projectMap.get(row.project_id);
      rows.push([project.name, 'Project', amount]);
    }
  }

  if (format === 'csv') {
    let csv = 'Recipient,Type,Amount (₦)\n';
    csv += rows.map(r => `"${r[0]}","${r[1]}","${r[2]}"`).join('\n');
    res.header('Content-Type', 'text/csv');
    res.attachment(`donation-summary-${targetMonth}.csv`);
    return res.send(csv);
  }

  res.status(400).send('Invalid format requested');
});

// Admin Logout
app.get('/admin/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      logger.error('Logout error:', err);
      return res.status(500).send('Logout failed.');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});



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
    const name = sanitizeText(req.body.name);
    const description = sanitizeHtml(req.body.description || '');

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
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
  ],
  validateRequest,
  async (req, res, next) => {
    try {
      const { name, email } = req.body;
      const sanitizedName = sanitizeText(name);
      const sanitizedEmail = sanitizeEmail(email.toLowerCase());

      const password = req.body.password;

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
  const sanitizedName = sanitizeText(name);
  const sanitizedEmail = sanitizeEmail(email);

  const insertedStaff = await trx('staff')
    .insert({
      name: sanitizedName,
      email: sanitizedEmail,
      active: true
    })
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


// ✅ Login Form - GET
app.get('/login', (req, res) => {
  res.render('login', {
    csrfToken: res.locals.csrfToken,
    cspNonce: res.locals.cspNonce,
    error: req.query.error || null
  });
});



// ✅ Login Handler - POST
app.post(
  '/login',
  (req, res, next) => {
    // Log session info for debugging
    logger.debug(`[LOGIN] Session ID: ${req.sessionID}`);
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
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
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
        return res.status(401).render('login', {
          csrfToken: res.locals.csrfToken,
          cspNonce: res.locals.cspNonce,
          error: 'Invalid email or password'
        });
      }

      if (account.disabled) {
        return res.status(403).render('login', {
          csrfToken: res.locals.csrfToken,
          cspNonce: res.locals.cspNonce,
          error: 'This account has been disabled'
        });
      }

      const isMatch = await bcrypt.compare(password, account.password_hash);

      if (!isMatch) {
        return res.status(401).render('login', {
          csrfToken: res.locals.csrfToken,
          cspNonce: res.locals.cspNonce,
          error: 'Invalid email or password'
        });
      }

      // ✅ Success: Regenerate session and redirect
      req.session.regenerate(async err => {
        if (err) {
          logger.error('❌ Session regeneration failed:', err.message);
          return next(new AppError('Session regeneration failed', 500));
        }

        req.session.staffId = account.staff_id;
        req.session.accountId = account.id;

        // Clear any previous CSRF secrets – let middleware handle it
        delete req.session.csrfSecret;

        res.redirect(303, '/staff-dashboard');
      });

    } catch (err) {
      logger.error('Login error:', err.message);
      next(new AppError('Authentication failed.', 500));
    }
  }
);


// Forgot Password - Show Request Form
app.get('/forgot-password', (req, res) => {
  const csrfToken = res.locals.csrfToken;
  const cspNonce = res.locals.cspNonce;

  res.render('forgot-password', {
    csrfToken,
    cspNonce
  });
});

// Forgot Password - Handle Email Submission
app.post('/forgot-password', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
], validateRequest, async (req, res, next) => {
  try {
    // ✅ Sanitize and normalize email
    const normalizedEmail = sanitizeEmail(req.body.email.toLowerCase());

    // 🔍 Find account by sanitized email
    const account = await db('staff_accounts').where('email', normalizedEmail).first();

    if (account) {
      // ⚙️ Generate reset token
      const token = jwt.sign({ id: account.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const resetLink = `${process.env.FRONTEND_BASE_URL}/reset-password?token=${token}`;

      // 📨 Send reset link via email
      if (process.env.SENDGRID_API_KEY) {
        sgMail.setApiKey(process.env.SENDGRID_API_KEY);
        await sgMail.send({
          to: normalizedEmail,
          from: { name: 'Harvest Call Support', email: 'support@harvestcallafrica.org' },
          subject: 'Password Reset Instructions',
          html: `
            <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
            <p>This link will expire in 1 hour.</p>
          `
        });
      }

      logger.info(`Password reset link for ${normalizedEmail}: ${resetLink}`);
    }

    // ✅ Always respond the same way for security
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
    logger.error('Password reset request error:', err.message);
    next(new DatabaseError('Failed to process password reset request'));
  }
});

// GET: Password Reset Form - Displays form to reset password using token
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

  res.render('reset-password', {
    csrfToken,
    token,
    cspNonce: res.locals.cspNonce
  });
});

// POST: Handle password reset form submission
app.post('/reset-password', [
  body('newPassword')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }).withMessage('Passwords do not match'),
], validateRequest, async (req, res, next) => {
  const { token, newPassword } = req.body;

  try {
    // 🔍 Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).send(`
        <div style="text-align:center; padding:40px;">
          <h2 style="color:#d32f2f;">Invalid or Expired Token</h2>
          <p>The password reset token is invalid or has expired.</p>
          <a href="/forgot-password">Request a new one</a>
        </div>
      `);
    }

    const accountId = decoded.id;

    // 🧾 Get account from DB
    const account = await db('staff_accounts').where('id', accountId).first();
    if (!account) {
      return res.status(404).send(`<div>Account not found</div>`);
    }

    // ✅ Sanitize email before using it
    const sanitizedEmail = sanitizeEmail(account.email);

    // 🔐 Hash new password
    const hash = await bcrypt.hash(newPassword, BCRYPT_COST);

    // 💾 Update password in DB
    await db('staff_accounts')
      .where('id', accountId)
      .update({
        password_hash: hash,
        updated_at: new Date().toISOString()
      });

    // ✅ Log success
    logger.info(`✅ Password successfully reset for ${sanitizedEmail}`);

    // 📤 Redirect to login
    res.send(`
      <html>
        <body style="text-align:center; padding:40px;">
          <h2>Password Successfully Reset</h2>
          <p>Your password has been updated successfully.</p>
          <a href="/login" class="btn">Login with New Password</a>
        </body>
      </html>
    `);

  } catch (err) {
    logger.error('Password reset error:', err.message);
    next(new AppError('Password reset failed.', 500));
  }
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
  res.render('change-password', {
    csrfToken: token,
    cspNonce: res.locals.cspNonce
  });
});


// ✅ Change Password - POST
app.post('/change-password', requireStaffAuth, [
  body('old_password').isString().notEmpty().withMessage('Current password is required'),
  body('new_password')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('confirm_password')
    .custom((value, { req }) => {
      if (value !== req.body.new_password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
], validateRequest, async (req, res, next) => {
  try {
    const { old_password, new_password } = req.body;
    const staffId = req.session.staffId;

    // Fetch account from DB
    const account = await db('staff_accounts').where('staff_id', staffId).first();
    if (!account) {
      return res.status(404).send(`
        <div style="text-align:center; padding:40px;">
          <h2>Account Not Found</h2>
          <p>Your session may have expired. Please log in again.</p>
          <a href="/login" class="btn">Login Again</a>
        </div>
      `);
    }

    // Validate current password
    const isMatch = await bcrypt.compare(old_password, account.password_hash);
    if (!isMatch) {
      return res.status(400).render('change-password', {
        csrfToken: res.locals.csrfToken,
        cspNonce: res.locals.cspNonce,
        error: 'Current password is incorrect'
      });
    }

    // Hash and update new password
    const hash = await bcrypt.hash(new_password, BCRYPT_COST);

    await db('staff_accounts')
      .where('staff_id', staffId)
      .update({
        password_hash: hash,
        updated_at: new Date().toISOString()
      });

    // Regenerate session after password change
    req.session.regenerate((err) => {
      if (err) {
        return next(new AppError('Session regeneration failed.', 500));
      }
      req.session.staffId = account.staff_id;
      req.session.accountId = account.id;
      res.redirect('/staff-dashboard');
    });

  } catch (err) {
    logger.error('Password change error:', err.message);
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


// ✅ Index maintenance logic with locking
let isMaintenanceRunning = false;

async function runIndexMaintenance() {
  if (isMaintenanceRunning) {
    logger.info('🔄 Index maintenance already running, skipping...');
    return;
  }

  if (process.env.NODE_ENV === 'production') {
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
        try {
          await sgMail.send({
            to: process.env.ADMIN_EMAIL,
            from: 'server@harvestcallafrica.org',
            subject: 'Index Maintenance Failed',
            text: `Error: ${err.message}`
          });
        } catch (emailErr) {
          logger.warn('📧 Failed to send admin email:', emailErr.message);
        }
      }
    } finally {
      isMaintenanceRunning = false;
    }
  }
}

// ✅ Server startup
async function startServer() {
  try {
    logger.info('⏳ Initializing database...');
    await initializeDatabase();

    logger.info('🔧 Running initial index maintenance...');
    await runIndexMaintenance();

    logger.info('🚀 Starting Express server...');
    app.listen(PORT, () => {
      logger.info(`✅ Server is running on port ${PORT}`);

      // Run hourly index maintenance check
      setInterval(() => {
        const now = new Date();
        if (now.getUTCDay() === 0 && now.getUTCHours() === 2) {
          runIndexMaintenance();
        }
      }, 60 * 60 * 1000); // Every hour
    });

  } catch (err) {
    logger.error('❌ Failed to start server:', err);
    try {
      await notifyAdmin('Critical App Crash', err.stack);
    } catch (notifyErr) {
      logger.warn('📧 Failed to notify admin of startup failure.', notifyErr.message);
    }
    process.exit(1);
  }
}

// ✅ Handle graceful shutdown
process.on('SIGINT', async () => {
  try {
    await notifyAdmin('🔻 Server Shutdown', 'The server is shutting down via SIGINT.');
  } catch (e) {
    logger.warn('⚠️ Failed to notify admin of shutdown.');
  }
  await db.destroy();
  logger.info('🔌 Database connection closed.');
  process.exit(0);
});

startServer();
