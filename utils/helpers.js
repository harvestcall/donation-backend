// utils/helpers.js

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '<',
    '>': '>',
    '"': '&quot;',
    "'": '&#039;'
  }[m]));
}

module.exports = { escapeHtml };