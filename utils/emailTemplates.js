// utils/emailTemplates.js

function buildThankYouEmail({
  donorFirstName,
  formattedAmount,
  paymentReference,
  purposeText,
  donationDate
}) {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Thank You for Your Donation</title>
        <style>
          /* [Include all CSS styles from File 2] */
          body { font-family: 'Segoe UI', sans-serif; background-color: #f8f9fa; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; background: white; }
          .header { background: linear-gradient(135deg, #003366 0%, #2E7D32 100%); color: white; text-align: center; border-radius: 8px 8px 0 0; padding: 30px; }
          .content { padding: 30px; }
          .thank-you { font-size: 24px; color: #003366; margin-bottom: 25px; font-weight: 700; text-align: center; }
          .highlight { color: #E67E22; font-weight: 700; font-size: 20px; }
          .details-card { background: #fdf5e6; padding: 25px; border-radius: 12px; margin: 25px 0; border: 1px solid #f0e6d6; }
          .detail-row { display: flex; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #f0e6d6; }
          .detail-label { font-weight: 600; color: #8D6E63; min-width: 120px; }
          .detail-value { flex: 1; font-weight: 500; }
          .impact-statement { font-style: italic; color: #2E7D32; margin: 30px 0; padding: 20px; background: #e8f5e9; border-radius: 8px; text-align: center; border-left: 4px solid #2E7D32; }
          .cta-button { display: block; width: 70%; max-width: 300px; margin: 30px auto; padding: 16px; background: #E67E22; color: white !important; text-align: center; text-decoration: none; font-weight: 700; font-size: 18px; border-radius: 8px; transition: all 0.3s ease; }
          .cta-button:hover { background: #d35400; transform: translateY(-2px); }
          .signature { margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 20px; text-align: center; }
          .footer { text-align: center; margin-top: 40px; font-size: 14px; color: #8D6E63; }
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
            <p>We're incredibly grateful for your generous donation of <span class="highlight">${formattedAmount}</span> to Harvest Call Ministries.</p>
            <div class="details-card">
              <div class="detail-row"><div class="detail-label">Reference:</div><div class="detail-value">${paymentReference}</div></div>
              <div class="detail-row"><div class="detail-label">Donation Type:</div><div class="detail-value">${donationType}</div></div>
              <div class="detail-row"><div class="detail-label">Purpose:</div><div class="detail-value">${purposeText}</div></div>
              <div class="detail-row"><div class="detail-label">Date:</div><div class="detail-value">${donationDate}</div></div>
            </div>
            <p class="impact-statement">"Your partnership enables indigenous missionaries to bring the Gospel to unreached communities."</p>
            <a href="https://harvestcallafrica.org/impact " class="cta-button">See How Your Donation Makes an Impact</a>
            <div class="signature">
              <p>With heartfelt gratitude,</p>
              <p><strong>The Harvest Call Ministries Team</strong></p>
              <p>Abuja, Nigeria</p>
            </div>
          </div>
          <div class="footer">
            <p>Harvest Call Ministries &bull; Abuja, Nigeria</p>
            <p><a href="https://harvestcallafrica.org ">harvestcallafrica.org</a> &bull; <a href="mailto:info@harvestcallafrica.org">info@harvestcallafrica.org</a></p>
            <p>You're receiving this email because you made a donation to Harvest Call Ministries.</p>
          </div>
        </div>
      </body>
    </html>
  `;
}

module.exports = {
  buildThankYouEmail
};