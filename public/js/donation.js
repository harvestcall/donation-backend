document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('donationForm');
  const emailInput = document.getElementById('email');
  const nameInput = document.getElementById('name');
  const amountInput = document.getElementById('amount');
  const purposeInput = document.getElementById('purpose');
  const donationTypeInput = document.getElementById('donationType');
  const submitBtn = document.getElementById('submitBtn');
  const loading = document.getElementById('loading');
  const errorContainer = document.getElementById('error-container');

  function getCsrfToken() {
    return document.querySelector("input[name='_csrf']").value;
  }

  function validateForm() {
    let isValid = true;

    if (!emailInput.value.includes('@')) {
      showError('Please enter a valid email address.');
      isValid = false;
    }

    if (!nameInput.value.trim()) {
      showError('Please enter your full name.');
      isValid = false;
    }

    if (!amountInput.value || parseFloat(amountInput.value) <= 0) {
      showError('Please enter a valid donation amount.');
      isValid = false;
    }

    return isValid;
  }

  function showError(message) {
    errorContainer.textContent = message;
    errorContainer.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function hideLoading() {
    loading.style.display = 'none';
    submitBtn.disabled = false;
  }

  function showLoading() {
    loading.style.display = 'block';
    submitBtn.disabled = true;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Clear previous errors
    errorContainer.style.display = 'none';

    // Validate inputs
    if (!validateForm()) return;

    // Prepare payload
    const payload = {
      email: emailInput.value.trim(),
      name: nameInput.value.trim(),
      phone: document.getElementById('phone').value.trim(),
      amount: parseFloat(amountInput.value),
      donationType: donationTypeInput.value,
      purpose: purposeInput.value
    };

    showLoading();

    try {
      const response = await fetch('/initialize-payment', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken()
        },
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Payment initialization failed');
      }

      const data = await response.json();
      window.location.href = data.authorization_url;
    } catch (err) {
      console.error('Donation error:', err.message);
      showError(`Error: ${err.message}`);
      hideLoading();
    }
  });
});