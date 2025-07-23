const jwt = require('jsonwebtoken');

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (token == null) return res.sendStatus(401); // No token present

    jwt.verify(token, JWT_ACCESS_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Invalid token

        req.user = user;
        next();
    });
};

const isEmailVerified = (req, res, next) => {
    if (!req.user.isEmailVerified) {
        return res.status(403).json({ message: 'Email not verified' });
    }
    next();
};

const authorize = (allowedRoles = []) => {
    return [
        authenticateToken,
        isEmailVerified,
        (req, res, next) => {
            try {
                const { id, role } = req.user;

                if (!id || !role) {
                    return res.status(401).json({ message: 'Unauthorized: Invalid token data' });
                }

                if (allowedRoles.length && !allowedRoles.includes(role)) {
                    return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
                }

                next();
            } catch (err) {
                console.error('Authorization error:', err);
                res.status(500).json({ message: 'Server error during authorization' });
            }
        }
    ];
};

module.exports = {
    authenticateToken,
    authorize
};