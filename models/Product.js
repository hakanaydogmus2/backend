const mongoose = require('mongoose');
const { z } = require('zod');

const productSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    price: { type: Number, required: true, min: 0 },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    stock: { type: Number, required: true, min: 0 },
    image: { type: String, required: true },
}, {
    timestamps: true
});

const productValidationSchema = z.object({
    name: z.string().min(3, "Name field cannot be empty"),
    description: z.string().min(3, "Description cannot be empty"),
    price: z.number().min(0, "Price cannot be negative"),
    categoryId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Must be a valid MongoDB ObjectId"),
    stock: z.number().min(0, "Stock cannot be negative"),
    image: z.url("Must be a valid image URL"),
});

function validateProduct(data) {
    return productValidationSchema.safeParse(data);
}

const Product = mongoose.model('Product', productSchema);
module.exports = {
    Product,
    validateProduct,
    productValidationSchema
};