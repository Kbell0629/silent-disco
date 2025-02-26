const fetch = require('node-fetch');

exports.handler = async function(event) {
  const { sourceId, amount, currency, locationId } = JSON.parse(event.body);
  const accessToken = 'EAAAlzamzg7GpOLRXZ0eumMKjBwhhdpJJ_v60Cjb7gY6VWdtp0NLfzZT04n-5Y6J';

  try {
    const response = await fetch('https://connect.squareupsandbox.com/v2/payments', {
      method: 'POST',
      headers: {
        'Square-Version': '2023-10-18',
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        idempotency_key: `${Date.now()}-${Math.random()}`, // Unique key per request
        source_id: sourceId,
        amount_money: { amount: amount, currency: currency },
        location_id: locationId,
        verification_token: null,
        autocomplete: false
      })
    });

    const result = await response.json();
    if (!response.ok) throw new Error(result.errors?.[0]?.detail || 'Preauthorization failed');
    return {
      statusCode: 200,
      body: JSON.stringify({ paymentId: result.payment.id })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};
