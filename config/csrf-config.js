// config/csrf-config.js

const isProduction = process.env.NODE_ENV === 'production';

const csrfCookieName = isProduction
  ? '__Host-hc-csrf-token'
  : 'hc-csrf-token';

const options = {
  getSecret: (req) => req.session.csrfSecret,
  storeSecret: (req, secret) => {
    req.session.csrfSecret = secret;
  },
  cookieName: csrfCookieName,
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
    path: '/', // required for __Host- prefix
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
};

module.exports = {
  csrfCookieName,
  options
};
