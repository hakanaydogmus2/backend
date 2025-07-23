const nodemailer = require('nodemailer');

async function sendPasswordResetEmail(email, token) {
    const resetUrl = `http://${process.env.HOST}:${process.env.PORT}/auth/resetPassword/${token}`;

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

async function sendEmailVerification(email, token) {
    const verificationUrl = `http://${process.env.HOST}:${process.env.PORT}/auth/verifyEmail/${token}`;
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
        subject: 'Email Verification',
        html: `
            <p>Lütfen e-posta adresinizi doğrulamak için aşağıdaki bağlantıya tıklayın:</p>
            <a href="${verificationUrl}">${verificationUrl}</a>
            <p>Bu bağlantı 1 hafta içinde geçerliliğini yitirecektir.</p>
        `
    };
    await transporter.sendMail(mailOptions);
}

module.exports = {
    sendPasswordResetEmail,
    sendEmailVerification
};