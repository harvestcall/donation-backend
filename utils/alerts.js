// utils/alerts.js
const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Notify the admin via email (e.g., when something critical breaks)
 */
async function notifyAdmin(subject, message) {
  if (!process.env.ADMIN_EMAIL) return;

  try {
    await sgMail.send({
      to: process.env.ADMIN_EMAIL,
      from: 'server@harvestcallafrica.org', // or whatever your sender is
      subject: subject,
      text: message
    });
    console.log('📧 Admin notified');
  } catch (err) {
    console.error('❌ Failed to send admin alert:', err.message);
  }
}

module.exports = { notifyAdmin };
