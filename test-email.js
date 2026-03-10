// test-email.js - Email functionality test
import 'dotenv/config';
import nodemailer from 'nodemailer';

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const MAIL_FROM = process.env.MAIL_FROM || SMTP_USER;

console.log('\n📧 Email Configuration Test\n');
console.log('─'.repeat(50));
console.log(`SMTP Host: ${SMTP_HOST}`);
console.log(`SMTP Port: ${SMTP_PORT}`);
console.log(`SMTP User: ${SMTP_USER}`);
console.log(`Mail From: ${MAIL_FROM}`);
console.log('─'.repeat(50));

if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
  console.error('❌ Missing SMTP credentials in .env file');
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS
  }
});

async function testEmail() {
  try {
    // Step 1: Verify connection
    console.log('\n1️⃣  Verifying SMTP connection...');
    await transporter.verify();
    console.log('✅ SMTP connection verified');

    // Step 2: Send test email
    console.log('\n2️⃣  Sending test email...');
    const testEmail = process.argv[2] || SMTP_USER;
    
    const info = await transporter.sendMail({
      from: MAIL_FROM,
      to: testEmail,
      subject: '✅ Base Credit Email Test - Success',
      text: 'This is a test email from your Base Credit banking platform.\n\nIf you received this, your email system is working correctly!',
      html: `
        <div style="font-family:Arial,sans-serif; max-width:600px; margin:0 auto; padding:20px;">
          <h2 style="color:#2563eb;">✅ Email System Test Successful</h2>
          <p>This is a test email from your <strong>Base Credit</strong> banking platform.</p>
          <p>If you received this message, your email configuration is working correctly!</p>
          <hr style="border:none; border-top:1px solid #e5e7eb; margin:20px 0;">
          <p style="font-size:12px; color:#6b7280;">
            Sent at: ${new Date().toLocaleString()}<br>
            From: ${MAIL_FROM}<br>
            SMTP Server: ${SMTP_HOST}:${SMTP_PORT}
          </p>
        </div>
      `
    });

    console.log('✅ Test email sent successfully!');
    console.log(`   Message ID: ${info.messageId || 'N/A'}`);
    console.log(`   Response: ${info.response || 'N/A'}`);
    console.log(`\n📬 Check inbox for: ${testEmail}`);
    console.log('\n✨ Your email system is working correctly!\n');

  } catch (error) {
    console.error('\n❌ Email test failed:', error.message);
    
    if (error.message.includes('Sender address rejected')) {
      console.log('\n🔧 TROUBLESHOOTING STEPS:');
      console.log('   1. Login to your Private Email control panel');
      console.log('   2. Verify the mailbox exists and is active');
      console.log('   3. Enable SMTP access for this mailbox');
      console.log('   4. Ensure the sender address matches an authorized mailbox');
      console.log('   5. Try using just the email address (no display name) in MAIL_FROM');
    } else if (error.message.includes('authentication')) {
      console.log('\n🔧 Check your SMTP credentials:');
      console.log('   - SMTP_USER should be your full email address');
      console.log('   - SMTP_PASS should be your mailbox password');
    }
    
    process.exit(1);
  }
}

testEmail();
