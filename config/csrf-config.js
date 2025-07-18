// config/csrf-config.js
const isProduction = process.env.NODE_ENV === 'production';

const csrfCookieName = isProduction
  ? '__Host-hc-csrf-token'
  : 'hc-csrf-token';

const options = {
  // Leave getSecret to be overridden in server.js
  getSessionIdentifier: (req) => req.sessionID,
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: false, // Must be false to allow frontend access
    sameSite: 'lax',
    secure: isProduction,
    path: '/',
  },
  size: 64,
  getTokenFromRequest: (req) => req.body._csrf,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
};

module.exports = {
  csrfCookieName,
  options
};