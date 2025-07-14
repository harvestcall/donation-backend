// test/test-email.js

require('dotenv').config();
const sgMail = require('@sendgrid/mail');
const { buildThankYouEmail } = require('../utils/emailTemplates');

// ❗ Make sure this matches what your template expects
const sampleData = {
  donorFirstName: 'Chinwe',
  formattedAmount: '₦5,000.00',
  paymentReference: 'PAY-20250714-ABC123',
  purposeText: 'Staff Support -- Pastor Joseph Mwangi',
  donationDate: 'July 14, 2025'
};

async function testEmail() {
  // ✅ Set SendGrid API Key
  const apiKey = process.env.SENDGRID_API_KEY;
  if (!apiKey) {
    console.error('❌ SENDGRID_API_KEY is missing in .env');
    return;
  }

  sgMail.setApiKey(apiKey);

  // ✅ Build HTML Email
  try {
    const htmlContent = buildThankYouEmail(sampleData);
    console.log('✅ Email HTML generated successfully.');
    console.log(`📄 HTML Length: ${htmlContent.length} characters`);
  } catch (err) {
    console.error('❌ Failed to generate email:', err.message);
    return;
  }

  // ✅ Try Sending It
  const msg = {
  to: process.env.RECEIVER_EMAIL,
  from: {
    email: process.env.SENDER_EMAIL,
    name: 'Harvest Call Ministries'
  },
  subject: `Thank You, ${sampleData.donorFirstName}! Your Generosity is Making a Difference`,
  html: buildThankYouEmail(sampleData)
};

try {
  // ✅ Save HTML to file for preview
  const fs = require('fs');
  fs.writeFileSync('test-email-output.html', msg.html);
  console.log('📄 Email HTML saved to test-email-output.html');

  // ✅ Send email via SendGrid
  await sgMail.send(msg);
  console.log(`📧 Email sent to ${msg.to}`);
  console.log('✅ Test email was accepted by SendGrid');
} catch (error) {
  console.error('❌ Failed to send test email:', error.message);
  if (error.response && error.response.body) {
    console.error('📩 Full SendGrid response:', JSON.stringify(error.response.body, null, 2));
  }
}

}

// ✅ Run the test
testEmail();