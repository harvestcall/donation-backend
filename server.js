// Load environment variables
require('dotenv').config();


// Helper: Fetch name of staff or project
async function getDisplayName(type, id, db) {
  console.log(`🔍 Looking up ${type} ID: ${id}`);
  
  // Convert to number if it's a string
  const numericId = typeof id === 'string' ? parseInt(id) : id;
  
  if (!numericId || isNaN(numericId)) {
    console.log(`❌ Invalid ID: ${id}`);
    return null;
  }

  try {
    console.log(`🔍 Querying database for ${type} with ID: ${numericId}`);
    
    // Get table name (use explicit name for safety)
    const table = type === 'staff' ? 'staff' : 'projects';
    const result = await db(table).where('id', numericId).first();
    
    if (result) {
      console.log(`✅ Found ${type}:`, result);
      return result.name;
    } else {
      console.log(`❌ No ${type} found with ID: ${numericId}`);
      
      // List all records to help debug
      const allRecords = await db(table).select('*');
      console.log(`📋 All ${type} records:`, allRecords);
      
      return null;
    }
  } catch (err) {
    console.error(`❌ Database error:`, err);
    return null;
  }
}

// Load database connection
const db = require('./db');
console.log("🛠 Using DB Connection:", db.client.config.connection);
console.log("🌍 Running in environment:", process.env.NODE_ENV);


// Run migration automatically (creates donations table if missing)
async function initializeDatabase() {
  try {
    // Run migrations
    await db.migrate.latest();
    console.log('📦 Migrations completed');
    
    // Run seeds
    await db.seed.run();
    console.log('🌱 Database seeded');
    
    // Verify staff records
    const staff = await db('staff').select('*');
    console.log('👥 Staff records:', staff);
  } catch (err) {
    console.error('❌ Database initialization error:', err.message);
  }
}
  // 👇 Don't forget this!
initializeDatabase();

// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const sgMail = require('@sendgrid/mail');
const app = express();

// Set up SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Middleware setup
app.use(bodyParser.json());
app.use(cors());

// Add this route above your payment initialization endpoint
app.get('/debug/staff', async (req, res) => {
  try {
    const staff = await db('staff').select('*');
    console.log('Staff Records:', staff);
    res.json(staff);
  } catch (error) {
    console.error('❌ Error fetching staff:', error);
    res.status(500).json({ error: 'Failed to load staff' });
  }
});

// Debug: Get all donations
app.get('/debug/donations', async (req, res) => {
  try {
    const donations = await db('donations').select('*');
    res.json(donations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Payment initialization endpoint
app.post('/initialize-payment', async (req, res) => {
  try {
    const { email, amount, currency, metadata } = req.body;

    const amountInKobo = amount * 100;

    const paymentData = {
      email,
      amount: amountInKobo,
      currency,
      metadata,
      callback_url: "https://yourfrontend.com/thank-you" // Replace with real page later
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
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});


// Webhook for payment verification
app.post('/webhook', async (req, res) => {
  try {
    const event = req.body;

    if (event.event === 'charge.success') {
      const paymentData = event.data;
      console.log('✅ Verified Payment:', paymentData.reference);
      console.log('🔎 Payment Metadata:', paymentData.metadata);

      // Save to database
      await db('donations').insert({
        email: paymentData.customer.email,
        reference: paymentData.reference,
        amount: paymentData.amount,
        currency: paymentData.currency,
        metadata: JSON.stringify(paymentData.metadata)
      });

      console.log('✅ Donation saved to database!');

      // Initialize variables with default values
      let purposeText = 'General Donation';

      // Check if we have staffId or projectId
      if (paymentData.metadata.staffId && paymentData.metadata.staffId.trim() !== '') {
  const staffName = await getDisplayName('staff', paymentData.metadata.staffId, db);
  if (staffName) {
    purposeText = `Staff Support -- ${staffName}`;
  }

// Keep projectId handling the same
      } else if (paymentData.metadata.projectId && paymentData.metadata.projectId.trim() !== '') {
        const projectName = await getDisplayName('projects', parseInt(paymentData.metadata.projectId), db);
        if (projectName) {
          purposeText = `Project Support -- ${projectName}`;
        }
      }

      console.log('Purpose:', purposeText);

      // Send beautiful thank-you email
      const donorFirstName = paymentData.metadata.donorName?.split(' ')[0] || 'Friend';
      const formattedAmount = paymentData.currency === 'USD' 
        ? `$${(paymentData.amount / 100).toFixed(2)}` 
        : `₦${(paymentData.amount / 100).toLocaleString()}`;
      
      const donationDate = new Date().toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      });


      await sgMail.send({
        to: paymentData.customer.email,
        from: {
          name: 'Harvest Call Ministries',
          email: 'giving@harvestcallafrica.org'
        },
        subject: `Thank You, ${donorFirstName}! Your Generosity is Making a Difference`,
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
                <h2 class="thank-you">Thank You, ${donorFirstName}!</h2>
                
                <p>We're incredibly grateful for your generous donation of <span class="highlight">${formattedAmount}</span> to Harvest Call Ministries. Your support is making a tangible difference in advancing God's kingdom across Africa.</p>
                
                <div class="details-card">
                  <div class="detail-row">
                    <div class="detail-label">Reference:</div>
                    <div class="detail-value">${paymentData.reference}</div>
                  </div>
                  <div class="detail-row">
                    <div class="detail-label">Donation Type:</div>
                    <div class="detail-value">${paymentData.metadata.donationType}</div>
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

      console.log('📧 Beautiful thank-you email sent via SendGrid!');
    }

    res.status(200).send('Webhook received');

  } catch (error) {
    console.error('❌ Error processing webhook:', error.message);
    res.status(400).json({ error: error.message });
  }
});


// Set port
const PORT = process.env.PORT || 5000;

app.get('/admin/donations', async (req, res) => {
  try {
    const donations = await db('donations').orderBy('id', 'desc');

    let tableRows = donations.map(d => {
      const metadata = JSON.parse(d.metadata || '{}');
      const donorName = metadata.donorName || '-';
      const purpose = metadata.purpose || '-';
      const donationType = metadata.donationType || '-';
      const currency = d.currency || 'NGN';
      const amount = currency === 'USD'
        ? `$${(d.amount / 100).toFixed(2)}`
        : `₦${(d.amount / 100).toLocaleString()}`;
      const status = 'success'; // Later: make dynamic if needed
      const reference = d.reference;
      const date = new Date(d.created_at || d.timestamp || Date.now()).toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      });

      return `
        <tr>
          <td>${donorName}</td>
          <td>${d.email}</td>
          <td>${amount}</td>
          <td>${currency}</td>
          <td>${purpose}</td>
          <td>${donationType}</td>
          <td>${reference}</td>
          <td>${date}</td>
          <td><span class="status success">Success</span></td>
          <td class="actions">
            <button class="action-btn"><i class="fas fa-eye"></i></button>
            <button class="action-btn"><i class="fas fa-receipt"></i></button>
          </td>
        </tr>
      `;
    }).join('');

    res.send(`<!DOCTYPE html>
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
  } catch (error) {
    console.error('❌ Error loading admin dashboard:', error.message);
    res.status(500).send('Something went wrong.');
  }
});

// Get all active staff
app.get('/staff', async (req, res) => {
  try {
    const staff = await db('staff').where({ active: true }).orderBy('name');
    res.json(staff);
  } catch (error) {
    console.error('❌ Error fetching staff:', error.message);
    res.status(500).json({ error: 'Failed to load staff list' });
  }
});

// Get all projects
app.get('/projects', async (req, res) => {
  try {
    const projects = await db('projects').orderBy('name');
    res.json(projects);
  } catch (error) {
    console.error('❌ Error fetching projects:', error.message);
    res.status(500).json({ error: 'Failed to load project list' });
  }
});

// Admin Summary Dashboard
app.get('/admin/summary', async (req, res) => {
  try {
    const donations = await db('donations').orderBy('created_at', 'desc');

    // Parse target month from query or use current
    const targetMonth = req.query.month || new Date().toISOString().slice(0, 7); // YYYY-MM
    const [year, month] = targetMonth.split('-').map(Number);
    const monthStart = new Date(year, month - 1, 1);
    const monthEnd = new Date(year, month, 0, 23, 59, 59);

    const filtered = donations.filter(d => {
      const date = new Date(d.created_at || d.timestamp || Date.now());
      return date >= monthStart && date <= monthEnd;
    });

    const summary = {
      total: 0,
      totalStaff: 0,
      totalProject: 0,
      donors: new Set(),
      records: {}
    };

    for (const d of filtered) {
      let metadata = {};
      try {
        metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
      } catch (err) {
        console.error('❌ Bad metadata:', d.metadata);
        continue;
      }

      const amount = d.amount / 100;
      summary.total += amount;
      summary.donors.add(d.email);

      let key = null;
      let label = '';

      if (metadata.staffId) {
        const staff = await db('staff').where('id', parseInt(metadata.staffId)).first();
        key = `staff-${metadata.staffId}`;
        label = `Staff – ${staff?.name || 'Unknown Staff'}`;
        summary.totalStaff += amount;
      } else if (metadata.projectId) {
        const project = await db('projects').where('id', parseInt(metadata.projectId)).first();
        key = `project-${metadata.projectId}`;
        label = `Project – ${project?.name || 'Unknown Project'}`;
        summary.totalProject += amount;
      }

      if (key) {
        if (!summary.records[key]) summary.records[key] = { label, total: 0 };
        summary.records[key].total += amount;
      }
    }

    const donorCount = summary.donors.size;
    const avgGift = donorCount ? (summary.total / donorCount).toFixed(2) : 0;

    const current = new Date(year, month - 1);
    const prevMonth = new Date(current);
    prevMonth.setMonth(current.getMonth() - 1);
    const nextMonth = new Date(current);
    nextMonth.setMonth(current.getMonth() + 1);

    const format = date => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
    const prev = format(prevMonth);
    const next = format(nextMonth);
    const title = current.toLocaleString('default', { year: 'numeric', month: 'long' });

    // Generate beautiful HTML dashboard
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Donation Summary Dashboard - Harvest Call Africa</title>
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
                        <p>Harvest Call Ministries - Monthly Contributions Report</p>
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
                <div class="current-month">${title}</div>
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
                                        <div>${r.label}</div>
                                    </div>
                                </td>
                                <td class="amount">₦${r.total.toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
            
            <div class="footer">
                <p>Harvest Call Ministries • Generated on ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
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
    console.error('❌ Summary error:', err.message);
    res.status(500).send(`
      <div style="font-family: Arial; padding: 30px; text-align: center;">
        <h2 style="color: #d32f2f;">Error Loading Summary</h2>
        <p>${err.message}</p>
        <a href="/admin/summary" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #003366; color: white; text-decoration: none; border-radius: 4px;">
          Try Again
        </a>
      </div>
    `);
  }
});


// Staff-Specific Dashboard
app.get('/staff-dashboard', async (req, res) => {
  try {
    const staffId = req.query.staffId;
    const monthParam = req.query.month; // e.g., "2025-06"

    if (!staffId) {
      return res.status(400).send('Missing staffId');
    }

    const staff = await db('staff').where('id', parseInt(staffId)).first();
    if (!staff) return res.status(404).send('Staff not found');

    // Determine current month or use query
    const today = new Date();
    const current = monthParam
      ? new Date(monthParam + '-01')
      : new Date(today.getFullYear(), today.getMonth(), 1);

    const monthKey = current.toLocaleString('default', { year: 'numeric', month: 'long' });
    const monthStart = new Date(current.getFullYear(), current.getMonth(), 1);
    const monthEnd = new Date(current.getFullYear(), current.getMonth() + 1, 0);

    const donations = await db('donations')
      .whereBetween('created_at', [monthStart.toISOString(), monthEnd.toISOString()])
      .orderBy('created_at', 'desc');

    const filtered = donations.filter(d => {
      try {
        const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
        return metadata.staffId === String(staffId);
      } catch (err) {
        console.error('❌ Bad metadata:', d.metadata);
        return false;
      }
    });

    // Calculate totals
    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 ? (totalAmount / donorCount).toFixed(2) : 0;

    // Month navigation helpers
    function prevMonth(date) {
      const d = new Date(date.getFullYear(), date.getMonth() - 1, 1);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    }

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
        <title>${staff.name} - Staff Dashboard</title>
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
                        <h1>${staff.name}</h1>
                        <p>Staff Support Dashboard</p>
                    </div>
                </div>
                <div class="controls">
                    <a href="/" class="btn">
                        <i class="fas fa-home"></i> Main Dashboard
                    </a>
                </div>
            </div>
            
            <div class="month-nav">
                <a href="/staff-dashboard?staffId=${staffId}&month=${prevMonth(current)}" class="nav-btn">
                    <i class="fas fa-chevron-left"></i>
                </a>
                <div class="current-month">${monthKey}</div>
                <a href="/staff-dashboard?staffId=${staffId}&month=${nextMonth(current)}" class="nav-btn">
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
                
                ${filtered.length === 0 ? `
                    <div class="no-donations">
                        <i class="fas fa-inbox"></i>
                        <h3>No Donations This Month</h3>
                        <p>Your supporters haven't made any contributions for ${monthKey} yet. Share your ministry story to encourage giving!</p>
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
                                const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
                                const donationDate = new Date(d.created_at);
                                return `
                                <tr>
                                    <td>
                                        <div class="donor-name">
                                            <div class="donor-icon">
                                                <i class="fas fa-user"></i>
                                            </div>
                                            <div>${metadata.donorName || 'Anonymous Supporter'}</div>
                                        </div>
                                    </td>
                                    <td class="amount">₦${(d.amount / 100).toLocaleString()}</td>
                                    <td><span class="type ${metadata.donationType === 'recurring' ? '' : 'one-time'}">${metadata.donationType || 'one-time'}</span></td>
                                    <td class="reference">${d.reference}</td>
                                    <td>${donationDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</td>
                                </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                `}
            </div>
            
            <div class="footer">
                <p>Harvest Call Ministries • Generated on ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
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
    console.error('❌ Staff dashboard error:', err.message);
    res.status(500).send(`
      <div style="font-family: Arial; padding: 30px; text-align: center;">
        <h2 style="color: #d32f2f;">Error Loading Dashboard</h2>
        <p>${err.message}</p>
        <a href="/staff-dashboard?staffId=${staffId}" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #003366; color: white; text-decoration: none; border-radius: 4px;">
          Try Again
        </a>
      </div>
    `);
  }
});

// Project-Specific Dashboard
app.get('/project-dashboard', async (req, res) => {
  try {
    const projectId = req.query.projectId;
    const monthParam = req.query.month;

    if (!projectId) {
      return res.status(400).send('Missing projectId');
    }

    const project = await db('projects').where('id', parseInt(projectId)).first();
    if (!project) return res.status(404).send('Project not found');

    // Determine current or selected month
    const today = new Date();
    const current = monthParam
      ? new Date(monthParam + '-01')
      : new Date(today.getFullYear(), today.getMonth(), 1);

    const monthKey = current.toLocaleString('default', { year: 'numeric', month: 'long' });
    const monthStart = new Date(current.getFullYear(), current.getMonth(), 1);
    const monthEnd = new Date(current.getFullYear(), current.getMonth() + 1, 0);

    const donations = await db('donations')
      .whereBetween('created_at', [monthStart.toISOString(), monthEnd.toISOString()])
      .orderBy('created_at', 'desc');

    const filtered = donations.filter(d => {
      try {
        const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
        return metadata.projectId === String(projectId);
      } catch (err) {
        console.error('❌ Bad metadata:', d.metadata);
        return false;
      }
    });

    // Calculate totals
    const totalAmount = filtered.reduce((sum, d) => sum + d.amount, 0) / 100;
    const donorCount = new Set(filtered.map(d => d.email)).size;
    const avgDonation = donorCount > 0 ? (totalAmount / donorCount).toFixed(2) : 0;

    // Month navigation helpers
    function prevMonth(date) {
      const d = new Date(date.getFullYear(), date.getMonth() - 1, 1);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    }

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
        <title>${project.name} - Project Dashboard</title>
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
                        <h1>${project.name}</h1>
                        <p>${project.description || 'Project funding dashboard'}</p>
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
                <div class="current-month">${monthKey}</div>
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
                        <p>This project hasn't received any contributions for ${monthKey} yet. Share the impact to encourage support!</p>
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
                                const metadata = typeof d.metadata === 'string' ? JSON.parse(d.metadata) : d.metadata || {};
                                const donationDate = new Date(d.created_at);
                                return `
                                <tr>
                                    <td>
                                        <div class="donor-name">
                                            <div class="donor-icon">
                                                <i class="fas fa-user"></i>
                                            </div>
                                            <div>${metadata.donorName || 'Anonymous Supporter'}</div>
                                        </div>
                                    </td>
                                    <td class="amount">₦${(d.amount / 100).toLocaleString()}</td>
                                    <td><span class="type ${metadata.donationType === 'recurring' ? '' : 'one-time'}">${metadata.donationType || 'one-time'}</span></td>
                                    <td class="reference">${d.reference}</td>
                                    <td>${donationDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</td>
                                </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                `}
            </div>
            
            <div class="footer">
                <p>Harvest Call Ministries • Generated on ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
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
    console.error('❌ Project dashboard error:', err.message);
    res.status(500).send(`
      <div style="font-family: Arial; padding: 30px; text-align: center;">
        <h2 style="color: #d32f2f;">Error Loading Dashboard</h2>
        <p>${err.message}</p>
        <a href="/project-dashboard?projectId=${projectId}" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #003366; color: white; text-decoration: none; border-radius: 4px;">
          Try Again
        </a>
      </div>
    `);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
