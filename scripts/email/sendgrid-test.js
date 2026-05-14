import sgMail from '@sendgrid/mail';
import dotenv from 'dotenv';

dotenv.config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const msg = {
  to: 'mastereric010@gmail.com',
  from: 'support@basecrypto.help',
  subject: 'Test Email',
  text: 'SendGrid API is working!',
  html: '<h1>SendGrid API is working!</h1>',
};

sgMail
  .send(msg)
  .then(() => {
    console.log('Email sent successfully!');
  })
  .catch((error) => {
    console.error(error);
  });