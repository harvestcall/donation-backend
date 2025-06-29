// utils/formatCurrency.js

const currencySymbols = {
  USD: '$',
  NGN: '₦',
  EUR: '€',
  GBP: '£',
  GHS: '₵',
  CAD: 'C$',
  AUD: 'A$',
  ZAR: 'R',
  JPY: '¥'
};

function formatCurrency(amountInCents, currency) {
  const symbol = currencySymbols[currency] || '';
  const amount = (amountInCents / 100).toLocaleString();

  return symbol
    ? `${symbol}${amount}`
    : `${amount} (${currency})`; // fallback for unknown currency
}

module.exports = formatCurrency;
