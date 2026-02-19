const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;

if (!secret) {
  throw new Error('JWT_SECRET is not defined');
}

const payload = {
  role: 'authenticated',
  email: 'info@shenzhenswift.online'
};

const token = jwt.sign(payload, secret, {
  expiresIn: '1h',
  issuer: 'your-app',
  audience: 'your-users'
});

console.log(token);
