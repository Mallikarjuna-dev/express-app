const mongoose = require("mongoose");

const blacklistedTokenSchema = mongoose.Schema({
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: "10d" }
});

module.exports = mongoose.model("BlacklistedToken", blacklistedTokenSchema);

