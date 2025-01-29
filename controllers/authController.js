const bcrypt = require("bcrypt");
const User = require("../models/User");
const genarateToken = require("../config/genarateToken");
const BlackListedToken = require("../models/BlackListedToken");

const registerUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            res.status(400);
            throw new Error("Please enter all the feilds!");
        }

        //   Check user exists or not
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: "User already exists!" })
            // throw new Error("User email already exists!");
        }

        // hash password
        // const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, 10);

        //   create user
        const user = await User.create({
            email,
            password: hashedPassword,
        });

        if (user) {
            res.status(201).json({
                email: user.email,
                token: genarateToken(user),
                message: "User registerd successfully."
            });
        }

    } catch (error) {
        res.status(400);
        throw new Error("Internal server error", error);
    }
}


const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            res.status(400);
            throw new Error("Invalid credentials!");
        }
        const token = genarateToken(user);
        res.status(201).json({
            email,
            token
        })

    } catch (error) {
        res.status(400);
        throw new Error("Invalid user data.");
    }
}

const logoutUser = async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
       return res.status(401).json("unauthorized")
    }

    const blacklisted = await BlackListedToken({ token });
    if (blacklisted) {
        res.status(201).json({ message: "Logged out successfully" })
    }
}


const refreshUser = async (req, res) => {
    const { refreshToken } = req.query.refreshToken;

    if (!refreshToken) {
        res.status(401).json("Unauthorized")
    }

    jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
        if (err) {
            res.status(403).json("Invalid refresh token");
        }

        const token = genarateToken(user);
        res.json(token);
    });
}

module.exports = { registerUser, loginUser, logoutUser, refreshUser }