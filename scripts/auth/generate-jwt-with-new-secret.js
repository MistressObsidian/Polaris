const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;

if (!secret) {
  throw new Error('JWT_SECRET not set in environment');
}

const payload = {
  role: 'confirmed',
  email: 'info@shenzhenswift.online'
};

const token = jwt.sign(payload, secret, {
  algorithm: 'HS256',
  expiresIn: '1h'
});

console.log(token);
