const jwt = require('jsonwebtoken');

// Replace with your actual secret
const secret = 'e4f9c7b1d2a38f0c6e9d5b4a7c2f8e1d9b6a3f4c8d7e2a5b1c9f6d3a7b8e4c2f';

// Example payload (customize as needed)
const payload = {
  role: 'authenticated',
  email: 'your@email.com'
};

// Generate token
const token = jwt.sign(payload, secret, { expiresIn: '1h' });
console.log(token);