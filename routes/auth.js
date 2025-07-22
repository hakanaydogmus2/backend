const express = require('express');
const { User, validateUser } = require('../models/User');
const bcrypt = require('bcrypt');

const router = express.Router();

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
        console.log('Valid Password:', validPassword);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        res.status(200).json({ message: 'Login successful', user: { id: user._id, username: user.username, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});
module.exports = router;