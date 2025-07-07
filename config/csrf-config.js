// config/csrf-config.js
const isProduction = process.env.NODE_ENV === 'production';

const csrfCookieName = isProduction
  ? "__Host-hc-csrf-token"
  : "hc-csrf-token";

module.exports = {
  csrfCookieName,
  options: {
    getSecret: () => process.env.SESSION_SECRET,
    cookieName: csrfCookieName,
    cookieOptions: {
      sameSite: "lax",
      path: "/",
      secure: isProduction,
      httpOnly: true,
    },
    size: 64,
    ignoredMethods: ["GET", "HEAD", "OPTIONS"]
  }
};
