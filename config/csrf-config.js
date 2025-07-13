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
    httpOnly: false, // ✅ Allow JS to read the cookie
    sameSite: 'lax',
    secure: isProduction,
    path: '/', // required for __Host-
  },
  size: 64,
  getTokenFromRequest: (req) => req.body._csrf,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
};

module.exports = {
  csrfCookieName,
  options
};