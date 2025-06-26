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

app.get('/admin/donations', async (req, res) => {
  try {
    const donations = await db('donations').orderBy('id', 'desc');

    let tableRows = donations.map(d => {
      const metadata = JSON.parse(d.metadata || '{}');
      const donorName = metadata.donorName || '-';
      const purpose = metadata.purpose || '-';
      const donationType = metadata.donationType || '-';
      const date = new Date(d.created_at || d.timestamp || Date.now()).toLocaleDateString();

      return `
        <tr>
          <td>${donorName}</td>
          <td>${d.email}</td>
          <td>₦${(d.amount / 100).toLocaleString()}</td>
          <td>${d.currency}</td>
          <td>${purpose}</td>
          <td>${donationType}</td>
          <td>${d.reference}</td>
          <td>${date}</td>
        </tr>`;
    }).join('');

    const html = `
      <html>
        <head>
          <title>Donations Admin</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 30px; }
            h2 { color: #003366; }
            table { border-collapse: collapse; width: 100%; }
            th, td { padding: 10px; border: 1px solid #ccc; text-align: left; }
            th { background-color: #f4f4f4; }
            tr:nth-child(even) { background-color: #f9f9f9; }
          </style>
        </head>
        <body>
          <h2>🧾 Donation Records</h2>
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
              </tr>
            </thead>
            <tbody>
              ${tableRows}
            </tbody>
          </table>
        </body>
      </html>
    `;

    res.send(html);
  } catch (error) {
    console.error('❌ Error loading donations:', error.message);
    res.status(500).send('Something went wrong.');
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
