const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { z } = require('zod');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: { type: String },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    refreshToken: { type: String, default: null },
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null }
});

// Zod schema for validation
const userZodSchema = z.object({
    username: z.string().min(3),
    email: z.email(),
    password: z.string().min(6),
    role: z.enum(['user', 'admin']).optional(),
    refreshToken: z.string().nullable().optional(),
    resetPasswordToken: z.string().nullable().optional(),
    resetPasswordExpires: z.date().nullable().optional()
});

// Example validation function
function validateUser(data) {
    return userZodSchema.safeParse(data);
}


userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});


userSchema.methods.comparePassword = function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.resetPasswordExpires = Date.now() + 3600000; // 1 saat geçerli

    return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = {
    User,
    validateUser,
    userZodSchema
};