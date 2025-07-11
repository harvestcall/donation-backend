// config/csrf-config.js
const isProduction = process.env.NODE_ENV === 'production';

const csrfCookieName = isProduction
  ? '__Host-hc-csrf-token'
  : 'hc-csrf-token';

const options = {
  getSecret: (req) => req.session.csrfSecret,
  getSessionIdentifier: (req) => req.sessionID, // ✅ Required by csrf-csrf
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax', // ✅ Better UX for most form-based apps
    secure: isProduction,
    path: '/', // required for __Host- prefix
  },
  size: 64,
  getTokenFromRequest: (req) => req.body._csrf, // ✅ Needed for form POSTs
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'] // ✅ Optional but safe to include
};

module.exports = {
  csrfCookieName,
  options
};
