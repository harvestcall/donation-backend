// Load environment variables
require('dotenv').config();

// Helper: Fetch name of staff or project
async function getDisplayName(type, id, db) {
  // Add extra safety check for numbers
  if (!id || isNaN(id)) return null;

  try {
    const result = await db(type).where('id', id).first();
    return result ? result.name : null;
  } catch (err) {
    console.error(`❌ Error fetching ${type} name:`, err.message);
    return null;
  }
}

// Load database connection
const db = require('./db');
// Run migration automatically (creates donations table if missing)
db.migrate.latest()
  .then(() => console.log('📦 Migrations completed'))
  .catch((err) => console.error('❌ Migration error:', err.message));

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

      // Determine who the donation is for
      let recipientType = '';
      let recipientName = '';
      let purposeText = 'General Donation';

      if (paymentData.metadata.staffId) {
        recipientType = 'staff';
        recipientName = await getDisplayName('staff', parseInt(paymentData.metadata.staffId), db);
        if (recipientName) {
          purposeText = `Staff Support -- ${recipientName}`;
        }
      } else if (paymentData.metadata.projectId) {
        recipientType = 'projects';
        recipientName = await getDisplayName('projects', parseInt(paymentData.metadata.projectId), db);
        if (recipientName) {
          purposeText = `Project Support -- ${recipientName}`;
        }
      }

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

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
