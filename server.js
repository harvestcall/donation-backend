// Load environment variables
require('dotenv').config();

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

      // Save to database
      await db('donations').insert({
        email: paymentData.customer.email,
        reference: paymentData.reference,
        amount: paymentData.amount,
        currency: paymentData.currency,
        metadata: JSON.stringify(paymentData.metadata)
      });

      console.log('✅ Donation saved to database!');

      // Send thank-you email using SendGrid
      const donorFirstName = paymentData.metadata.donorName?.split(' ')[0] || 'Friend';
const formattedAmount = (paymentData.amount / 100).toLocaleString();
const donationDate = new Date().toLocaleDateString('en-US', {
  year: 'numeric', month: 'long', day: 'numeric'
});

await sgMail.send({
  to: paymentData.customer.email,
  from: {
    name: 'Harvest Call Ministries',
    email: 'giving@harvestcallafrica.org'
  },
  subject: `Thank You, ${donorFirstName}! Your Donation is Received`,
  html: `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; color: #333; background-color: #f2f2f2; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; }
        .header { text-align: center; padding: 30px 0; }
        .logo { max-width: 140px; margin-bottom: 10px; }
        .content { padding: 20px; }
        .highlight { color: #E67E22; font-weight: bold; }
        .details { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .impact-statement { font-style: italic; color: #003366; margin: 25px 0; }
        .button {
          display: inline-block;
          background: #2E7D32;
          color: #fff !important;
          padding: 12px 24px;
          text-decoration: none;
          border-radius: 4px;
          margin: 15px 0;
        }
        .footer {
          text-align: center;
          margin-top: 40px;
          font-size: 12px;
          color: #888;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <img src="https://harvestcallafrica.org/logo.png" alt="Harvest Call Ministries" class="logo" />
        </div>

        <div class="content">
          <h2>Thank You, ${donorFirstName}!</h2>

          <p>Your generous donation of <span class="highlight">₦${formattedAmount}</span> has been received and will make a significant impact in advancing God's kingdom across Africa.</p>

          <div class="details">
            <p><strong>Reference Number:</strong> ${paymentData.reference}</p>
            <p><strong>Donation Type:</strong> ${paymentData.metadata.donationType}</p>
            <p><strong>Purpose:</strong> ${paymentData.metadata.purpose}</p>
            <p><strong>Date:</strong> ${donationDate}</p>
          </div>

          <p class="impact-statement">"Your support enables indigenous missionaries to bring the Gospel to unreached communities."</p>

          <p>We've attached your tax receipt to this email for your records.</p>

          <p>To see how your donation is making a difference:</p>
          <a href="https://harvestcallafrica.org/" class="button">View Our Impact</a>

          <p>If you have any questions about your donation, reply to this email or contact us at <a href="mailto:giving@harvestcallafrica.org">giving@harvestcallafrica.org</a>.</p>

          <p>With gratitude,<br><strong>The Harvest Call Ministries Team</strong></p>
        </div>

        <div class="footer">
          <p>Harvest Call Ministries • Abuja, Nigeria</p>
          <p><a href="https://harvestcallafrica.org" style="color: #2E7D32;">harvestcallafrica.org</a></p>
          <p>You’re receiving this email because you made a donation to Harvest Call Ministries.</p>
        </div>
      </div>
    </body>
    </html>
  `
});

console.log('📧 Branded thank-you email sent via SendGrid!');

    }

    res.status(200).send('Webhook received');

  } catch (error) {
    console.error('❌ Error saving payment:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Set port
const PORT = process.env.PORT || 5000;

// Add to your server.js file

// ======================
// ADMIN DASHBOARD SETUP
// ======================

// Install required packages: (run in terminal)
// npm install basic-auth

const auth = require('basic-auth');

// Simple authentication (change to your credentials)
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'harvestcall2023';

// Secure admin middleware
function authenticateAdmin(req, res, next) {
  const user = auth(req);
  
  if (!user || user.name !== ADMIN_USERNAME || user.pass !== ADMIN_PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="Harvest Call Admin"');
    return res.status(401).send('Authentication required');
  }
  
  next();
}

// Admin donations route
app.get('/admin/donations', authenticateAdmin, async (req, res) => {
  try {
    // Fetch donations from database
    const donations = await db('donations').orderBy('created_at', 'desc');
    
    // Build HTML
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Donations Admin - Harvest Call</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background: #f0f2f5; margin: 0; padding: 20px; color: #333; }
        .admin-container { max-width: 1200px; margin: 0 auto; }
        .admin-header { background: linear-gradient(135deg, #003366 0%, #2E7D32 100%); 
                        color: white; padding: 20px; border-radius: 8px; margin-bottom: 25px; }
        .admin-header h1 { margin: 0; display: flex; align-items: center; gap: 15px; }
        .admin-header i { font-size: 1.8rem; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                 gap: 15px; margin-bottom: 25px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .stat-card h3 { margin-top: 0; color: #666; font-size: 1rem; }
        .stat-card p { font-size: 1.8rem; font-weight: 700; margin: 10px 0; color: #003366; }
        .table-container { background: white; border-radius: 8px; overflow: hidden; 
                           box-shadow: 0 2px 8px rgba(0,0,0,0.05); overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 1000px; }
        th { background: #003366; color: white; text-align: left; padding: 15px; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #f0f7ff; }
        .status { display: inline-block; padding: 5px 10px; border-radius: 12px; font-size: 0.85rem; }
        .status-success { background: #d4edda; color: #155724; }
        .action-btn { background: #e9ecef; border: none; border-radius: 4px; padding: 6px 10px; 
                      cursor: pointer; margin-right: 5px; }
        .action-btn:hover { background: #E67E22; color: white; }
        .pagination { display: flex; gap: 10px; margin: 20px 0; justify-content: center; }
        .pagination-btn { padding: 8px 15px; background: white; border: 1px solid #ddd; 
                          border-radius: 4px; cursor: pointer; }
        .pagination-btn:hover { background: #f0f0f0; }
        .logout-btn { display: block; margin: 20px auto; padding: 10px 20px; background: #dc3545; 
                      color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }
        .logout-btn:hover { background: #c82333; }
      </style>
    </head>
    <body>
      <div class="admin-container">
        <div class="admin-header">
          <h1><i class="fas fa-hand-holding-heart"></i> Harvest Call Africa - Donation Records</h1>
        </div>
        
        <div class="stats">
          <div class="stat-card">
            <h3><i class="fas fa-donate"></i> Total Donations</h3>
            <p>₦${donations.reduce((sum, d) => sum + (d.amount / 100), 0).toLocaleString()}</p>
          </div>
          <div class="stat-card">
            <h3><i class="fas fa-users"></i> Total Donors</h3>
            <p>${new Set(donations.map(d => d.email)).size}</p>
          </div>
          <div class="stat-card">
            <h3><i class="fas fa-calendar"></i> Last 30 Days</h3>
            <p>${donations.filter(d => {
              const donationDate = new Date(d.created_at);
              const thirtyDaysAgo = new Date();
              thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
              return donationDate > thirtyDaysAgo;
            }).length}</p>
          </div>
        </div>
        
        <div class="table-container">
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
              ${donations.map(d => {
                const metadata = d.metadata ? JSON.parse(d.metadata) : {};
                const donorName = metadata.donorName || 'Anonymous';
                const purpose = metadata.purpose || 'General Fund';
                const donationType = metadata.donationType || 'One-time';
                const date = new Date(d.created_at).toLocaleDateString();
                
                return `
                <tr>
                  <td>${donorName}</td>
                  <td>${d.email}</td>
                  <td>${d.currency === 'NGN' ? '₦' : '$'}${(d.amount / 100).toLocaleString()}</td>
                  <td>${d.currency}</td>
                  <td>${purpose}</td>
                  <td>${donationType}</td>
                  <td>${d.reference}</td>
                  <td>${date}</td>
                  <td><span class="status status-success">Success</span></td>
                  <td>
                    <button class="action-btn" title="View Details"><i class="fas fa-eye"></i></button>
                    <button class="action-btn" title="Download Receipt"><i class="fas fa-receipt"></i></button>
                  </td>
                </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
        
        <div class="pagination">
          <button class="pagination-btn">1</button>
          <button class="pagination-btn">2</button>
          <button class="pagination-btn">3</button>
        </div>
        
        <button class="logout-btn" onclick="location.reload()">
          <i class="fas fa-sync-alt"></i> Refresh Data
        </button>
      </div>
      
      <script>
        // Simple logout functionality
        document.querySelector('.logout-btn').addEventListener('click', function() {
          if(confirm('Refresh donation data?')) {
            location.reload();
          }
        });
        
        // Action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
          btn.addEventListener('click', function() {
            const row = this.closest('tr');
            const donor = row.children[0].textContent;
            const amount = row.children[2].textContent;
            
            if(this.querySelector('i').classList.contains('fa-eye')) {
              alert('View details for: ' + donor + '\\nAmount: ' + amount);
            } else {
              alert('Download receipt for: ' + donor);
            }
          });
        });
      </script>
    </body>
    </html>
    `;
    
    res.send(html);
    
  } catch (error) {
    console.error('Error loading donations:', error);
    res.status(500).send(`
      <div style="padding: 20px; font-family: sans-serif;">
        <h2>Error Loading Donations</h2>
        <p>${error.message}</p>
        <button onclick="location.reload()">Try Again</button>
      </div>
    `);
  }
});

// ======================
// END ADMIN DASHBOARD
// ======================


// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
