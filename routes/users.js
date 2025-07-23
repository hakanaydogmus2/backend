const express = require('express');
const router = express.Router();
const { User } = require('../models/User');
const { authorize } = require('../middlewares/auth');


// Get all users
router.get('/', authorize(["admin"]), async(req, res) => {
    const users = await User.find();
    res.json(users);
});

// Get single user
router.get('/:id', async(req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Update user 
// TODO user should be able to update only their own data
router.put('/:id', authorize(['user']), async(req, res) => {
    try {
        if (req.user.id !== req.params.id) {
            return res.status(403).json({ error: '' });
        }
        const updated = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updated) return res.status(404).json({ error: 'User not found' });
        res.json(updated);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete user
router.delete('/:id', async(req, res) => {
    try {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

module.exports = router;