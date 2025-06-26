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
      await sgMail.send({
        to: paymentData.customer.email,
        from: {
          name: 'Harvest Call Ministries',
          email: 'giving@harvestcallafrica.org' // Verified sender
        },
        subject: 'Thank You for Your Donation',
        text: `Dear ${paymentData.metadata.donorName},

Thank you for your generous donation of ₦${paymentData.amount / 100} to Harvest Call Ministries.

Reference: ${paymentData.reference}
Donation Type: ${paymentData.metadata.donationType}
Purpose: ${paymentData.metadata.purpose}

We are deeply grateful for your partnership.

– Harvest Call Team`
      });

      console.log('📧 Thank-you email sent via SendGrid!');
    }

    res.status(200).send('Webhook received');

  } catch (error) {
    console.error('❌ Error saving payment:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Set port
const PORT = process.env.PORT || 5000;

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
