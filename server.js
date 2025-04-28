require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const app = express();
app.set('trust proxy', 1);

const db = require('./database');
const { encryptPrivateKey, decryptPrivateKey } = require('./encryptPrivateKey');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const authLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // Limit each IP to 5 requests per minute
    message: { error: "Too many login attempts, please try again later." }
});

// /register endpoint
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    db.run(
        `INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, password],
        function (err) {
            if (err) {
                console.error('Registration error:', err.message);
                return res.status(500).json({ error: "Registration failed" });
            }
            res.json({ message: "User registered successfully", userId: this.lastID });
        }
    );
});

// Start server
const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// /auth endpoint
app.post('/auth', authLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    db.get(
        `SELECT * FROM users WHERE username = ? AND password = ?`,
        [username, password],
        (err, user) => {
            if (err) {
                console.error('Authentication error:', err.message);
                return res.status(500).json({ error: "Authentication failed" });
            }

            if (!user) {
                return res.status(401).json({ error: "Invalid credentials" });
            }

            // Log authentication attempt
            const timestamp = new Date().toISOString();
            const ip = req.ip || req.connection.remoteAddress;

            db.run(
                `INSERT INTO auth_logs (userId, timestamp, ip) VALUES (?, ?, ?)`,
                [user.id, timestamp, ip],
                (err) => {
                    if (err) {
                        console.error('Logging error:', err.message);
                    }
                }
            );

            res.json({ message: "Authentication successful", userId: user.id });
        }
    );
});
