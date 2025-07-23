const express = require('express');
const router = express.Router();
const authorize = require('../middlewares/auth').authorize;
const { Category, validateCategory } = require('../models/Category');

// Create category
router.post('/', authorize(['admin']), async(req, res) => {
    const validation = validateCategory(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    try {
        const category = new Category(validation.data);
        await category.save();
        res.status(201).json(category);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all categories
router.get('/', async(req, res) => {
    try {
        const categories = await Category.find();
        res.json(categories);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.delete('/:id', authorize(['admin']), async(req, res) => {
    try {
        const deletedCategory = await Category.findByIdAndDelete(req.params.id);
        if (!deletedCategory) {
            return res.status(404).json({ error: 'Category not found' });
        }
        res.json({ message: 'Category deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update category
router.put('/:id', authorize(['admin']), async(req, res) => {
    const validation = validateCategory(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    try {
        const updatedCategory = await Category.findByIdAndUpdate(req.params.id, validation.data, { new: true });
        if (!updatedCategory) {
            return res.status(404).json({ error: 'Category not found' });
        }
        res.json(updatedCategory);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;