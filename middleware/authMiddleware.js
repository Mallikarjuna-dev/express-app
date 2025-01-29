const jwt = require('jsonwebtoken');
const BlackListedToken = require('../models/BlackListedToken');


const authenticateToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json("Unauthorized");
    }

    const blacklisted = await BlackListedToken.findOne({ token });
    if (blacklisted) {
        return res.status(401).json("Token revoked")
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json("Invalid token");
        }
        req.user = user;

        next();
    });
};

module.exports = authenticateToken;