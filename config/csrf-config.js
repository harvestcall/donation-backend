// config/csrf-config.js
const isProduction = process.env.NODE_ENV === 'production';

const csrfCookieName = isProduction
  ? '__Host-hc-csrf-token'
  : 'hc-csrf-token';

const options = {
  getSecret: (req) => req.session.csrfSecret,
  getSessionIdentifier: (req) => req.sessionID,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: false,
    sameSite: 'lax',
    secure: isProduction,
    path: '/',
    // ✅ Fix: only add domain in production
    ...(isProduction && { domain: '.harvestcallafrica.org' })
  },
  size: 64,
  getTokenFromRequest: (req) => req.body._csrf,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
};

module.exports = {
  csrfCookieName,
  options
};
