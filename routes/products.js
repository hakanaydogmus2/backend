const express = require('express');
const router = express.Router();
const { authorize } = require('../middlewares/auth');
const { Product, validateProduct } = require('../models/Product');

// Create product
router.post('/', authorize(['admin']), async(req, res) => {
    const validation = validateProduct(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    try {
        const product = new Product(validation.data);
        await product.save();
        res.status(201).json(product);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all products
router.get('/', async(req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get single product
router.get('/:id', async(req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.json(product);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Update product
router.put('/:id', authorize(['admin']), async(req, res) => {
    const validation = validateProduct(req.body);
    if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
    }

    try {
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, validation.data, { new: true });
        if (!updatedProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(updatedProduct);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});