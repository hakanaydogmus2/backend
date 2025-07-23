const mongoose = require('mongoose');
const { z } = require('zod');

const categorySchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
}, {
    timestamps: true
});

// Zod schema for validation
const categoryZodSchema = z.object({
    name: z
        .string()
        .min(3)
        .max(50)
        .regex(/^[a-zA-ZğüşıöçĞÜŞİÖÇ]+$/, "Category name must contain only letters"),
});

function validateCategory(data) {
    return categoryZodSchema.safeParse(data);
}
const Category = mongoose.model('Category', categorySchema);
module.exports = {
    Category,
    validateCategory,
    categoryZodSchema
};