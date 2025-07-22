const nodemailer = require('nodemailer');

async function sendPasswordResetEmail(email, token) {
    const resetUrl = `http://localhost:3001/auth/resetPassword/${token}`;

    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASSWORD
        }
    });

    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: email,
        subject: 'Password Reset Request',
        html: `
            <p>Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:</p>
            <a href="${resetUrl}">${resetUrl}</a>
            <p>Bu bağlantı 1 saat içinde geçerliliğini yitirecektir.</p>
        `
    };

    await transporter.sendMail(mailOptions);
}

module.exports = {
    sendPasswordResetEmail
};