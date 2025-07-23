const express = require('express');
const { User, validateUser } = require('../models/User');
const router = express.Router();
const { generateAccessToken, generateRefreshToken } = require('../utils/jwtHelper');
const jwt = require('jsonwebtoken');
const { sendPasswordResetEmail, sendEmailVerification } = require('../utils/emailHelper');
const crypto = require('crypto');
const { authorize } = require('../middlewares/auth');

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

router.post('/register', async(req, res) => {
    const validation = validateUser(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    const { username, email, password } = validation.data;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const newUser = new User({
            username,
            email,
            password,
            role: 'user', // Default role
        });

        await newUser.save();

        const verifyToken = newUser.generateEmailVerificationToken();
        await newUser.save();

        await sendEmailVerification(newUser.email, verifyToken);
        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.post('/login', async(req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User is not registered' });
        }
        if (!user.isEmailVerified) {
            return res.status(403).json({ message: 'Email not verified' });
        }
        const validPassword = await user.comparePassword(password);

        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = refreshToken;
        await user.save();

        res.status(200).json({
            message: 'Login successful',
            accessToken,
            refreshToken,
        });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.post('/refreshToken', authorize(['admin', 'user']), async(req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token required' });
    }
    console.log('Received refresh token:', refreshToken);

    try {

        const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const user = await User.findById(payload.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const newAccessToken = generateAccessToken(user);
        res.status(200).json({ accessToken: newAccessToken });

    } catch (err) {
        res.status(403).json({ message: 'Invalid refresh token', error: err.message });
    }
});


router.post('/logout', authorize(['admin', 'user']), async(req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ message: 'Refresh token required' });
    }
    try {
        const user = await User.findOne({ refreshToken });
        if (!user) {
            return res.status(400).json({ message: 'Invalid refresh token' });
        }
        user.refreshToken = null;
        await user.save();
        res.status(200).json({ message: 'Logout successful' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});


router.post('/changePassword', async(req, res) => {
    const { email, oldPassword, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        const validPassword = await user.comparePassword(oldPassword);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid old password' });
        }
        user.password = newPassword;
        await user.save();
        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});


// TODO always return 200, even if email is not found
router.post('/forgotPassword', async(req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        // Generate a password reset token and send it to the user's email
        const resetToken = user.generateResetToken();
        await user.save();

        sendPasswordResetEmail(user.email, resetToken);

        res.status(200).json({ message: 'Password reset email sent' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});


router.get('/resetPassword/:token', async(req, res) => {
    const { token } = req.params;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
        return res.status(400).send('Invalid or expired token');
    }

    res.send(`
        <form action="/auth/resetPassword/${token}" method="POST">
            <input type="password" name="newPassword" placeholder="New password" required />
            <button type="submit">Reset Password</button>
        </form>
    `);
});

router.post('/resetPassword/:token', async(req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    try {
        const user = await User.findOne({ resetPasswordToken: hashedToken, resetPasswordExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        user.password = newPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successful you can close the tab' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.get('/verifyEmail/:token', async(req, res) => {
    const { token } = req.params;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    try {

        const user = await User.findOne({ emailVerificationToken: hashedToken, emailVerificationExpires: { $gt: Date.now() } }); // one week 
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();
        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

module.exports = router;