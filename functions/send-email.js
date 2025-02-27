const nodemailer = require('nodemailer');

exports.handler = async function(event) {
  const { name, email, agreement, signature } = JSON.parse(event.body);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'se2login@gmail.com',
      pass: 'pldsmgtiludxodpr'
    }
  });

  const mailOptions = {
    from: 'se2login@gmail.com',
    to: email,
    bcc: 'se2login@gmail.com',
    subject: 'Your SE2 Silent Disco Rental Agreement',
    text: `Dear ${name},\n\nThank you for renting headphones from SE2 Silent Disco DBA and SE2 Events Inc.! Below is your signed rental agreement:\n\n${agreement}\n\nBest regards,\nSE2 Silent Disco DBA and SE2 Events Inc.`
  };

  // Only add signature attachment if signature is provided and valid
  if (signature && signature.startsWith('data:image/')) {
    const signatureBuffer = Buffer.from(signature.split(',')[1], 'base64');
    mailOptions.attachments = [{
      filename: 'signature.png',
      content: signatureBuffer,
      contentType: 'image/png'
    }];
    mailOptions.text += '\n\nYour signature is attached.';
  } else {
    console.log('No valid signature provided; skipping attachment.');
  }

  try {
    await transporter.sendMail(mailOptions);
    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Email sent successfully' })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};
