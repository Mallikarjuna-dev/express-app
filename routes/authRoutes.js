const express = require("express");
const { registerUser, loginUser, logoutUser, refreshUser } = require("../controllers/authController");
const authenticateToken = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser)
router.get("/logout", authenticateToken, logoutUser)
router.get("/refresh", refreshUser)

module.exports = router;