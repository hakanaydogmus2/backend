const express = require('express');
const { User, validateUser } = require('../models/User');
const bcrypt = require('bcrypt');
const router = express.Router();
const { generateAccessToken, generateRefreshToken } = require('../utils/jwtHelper');
const jwt = require('jsonwebtoken');

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

router.post('/register', async(req, res) => {
    const validation = validateUser(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    const { username, email, password, role } = validation.data;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const newUser = new User({
            username,
            email,
            password,
            role: role || 'user'
        });

        await newUser.save();

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
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const validPassword = await user.comparePassword(password);
        
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = refreshToken;
        await user.save();

        res.status(200).json(
            { 
                message: 'Login successful',
                accessToken,
                refreshToken,
            });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

router.post('/refresh-token', async(req, res) => {
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


router.post('/logout', async(req, res) => {
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

module.exports = router;