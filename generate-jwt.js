const jwt = require('jsonwebtoken');

// Replace with your actual secret
const secret = '8a636c4c9fc2c9043642f6744da9510bbf28bb86490001643337ade3a002c39e6db08185002c8bd72c64498cbd832ea3bb5b9d022389f87e2bb118ffbab50201';

// Example payload (customize as needed)
const payload = {
  role: 'authenticated',
  email: 'your@email.com'
};

// Generate token
const token = jwt.sign(payload, secret, { expiresIn: '1h' });
console.log(token);