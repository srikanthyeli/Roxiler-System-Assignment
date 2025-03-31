// Backend (Node.js + Express + SQLite)
const express = require('express');
const sqlite3 = require('better-sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require("express-validator");
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access denied' });
    
    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

const validateRegistration = [
    body("name").isLength({ min: 3 }).withMessage("Name must be at least 3 characters long"),
    body("email").isEmail().withMessage("Invalid email format"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    body("address").isLength({ min: 5 }).withMessage("Address must be at least 5 characters long"),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];
// Middleware for role-based access control
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        next();
    };
};

// Middleware for data validation
const validateRating = (req, res, next) => {
    const { user_id, store_id, rating } = req.body;
    if (!user_id || !store_id || rating < 1 || rating > 5) {
        return res.status(400).json({ message: 'Invalid rating data' });
    }
    next();
};

// SQLite Connection
const db = new sqlite3.Database('./store_rating.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS stores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        address TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        store_id INTEGER,
        rating INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(store_id) REFERENCES stores(id)
    )`);

});

// User Registration
app.post('/register', validateRegistration,async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    db.run(query, [name, email, hashedPassword, role], function(err) {
        if (err) return res.status(500).json(err);
        res.status(201).json({ message: 'User registered successfully!' });
    });
});

// User Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json(err);
        if (!user) return res.status(401).json({ message: 'User not found' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, role: user.role }, 'secretkey', { expiresIn: '1h' });
        res.json({ token });
    });
});

// Add new stores (Admin Only)
app.post('/stores', (req, res) => {
    const { name, email, address } = req.body;
    const query = 'INSERT INTO stores (name, email, address) VALUES (?, ?, ?)';
    db.run(query, [name, email, address], function(err) {
        if (err) return res.status(500).json(err);
        res.status(201).json({ message: 'Store added successfully!' });
    });
});

// Add new users (Admin Only)
app.post('/users', async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    db.run(query, [name, email, hashedPassword, role], function(err) {
        if (err) return res.status(500).json(err);
        res.status(201).json({ message: 'User added successfully!' });
    });
});

// Retrieve total number of users, stores, and ratings
app.get('/stats', (req, res) => {
    db.get('SELECT COUNT(*) AS users FROM users', (err, users) => {
        db.get('SELECT COUNT(*) AS stores FROM stores', (err, stores) => {
            db.get('SELECT COUNT(*) AS ratings FROM ratings', (err, ratings) => {
                if (err) return res.status(500).json(err);
                res.json({ users: users.users, stores: stores.stores, ratings: ratings.ratings });
            });
        });
    });
});

// List all stores
app.get('/stores', (req, res) => {
    const { name, address } = req.query;
    let query = 'SELECT * FROM stores';
    let params = [];
    if (name || address) {
        query += ' WHERE';
        if (name) {
            query += ' name LIKE ?';
            params.push(`%${name}%`);
        }
        if (address) {
            query += params.length ? ' AND address LIKE ?' : ' address LIKE ?';
            params.push(`%${address}%`);
        }
    }
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json(err);
        res.json(rows);
    });
});

// Submit ratings
app.post('/ratings', authenticateToken, validateRating, (req, res) => {
    const { user_id, store_id, rating } = req.body;
    const query = 'INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)';
    db.run(query, [user_id, store_id, rating], function(err) {
        if (err) return res.status(500).json(err);
        res.status(201).json({ message: 'Rating submitted successfully!' });
    });
});

app.listen(5000, () => console.log('Server running on port 5000'));
