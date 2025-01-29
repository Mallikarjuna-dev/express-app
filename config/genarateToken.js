const jwt = require("jsonwebtoken");

const generateToken = (user) => {
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, { expiresIn: '10d' });
    return { accessToken, refreshToken };
};

module.exports = generateToken;