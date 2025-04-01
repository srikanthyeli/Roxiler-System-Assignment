const express = require('express');
const path = require('path');
const sqlite3 = require('better-sqlite3');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Connect to SQLite database
const db = new sqlite3.Database(path.join(__dirname, 'store_rating.db'), (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        // Create tables with proper constraints and indexes
        db.serialize(() => {
            // Drop existing tables if they exist
            // db.run('DROP TABLE IF EXISTS ratings');
            // db.run('DROP TABLE IF EXISTS stores');
            // db.run('DROP TABLE IF EXISTS users');

            // Users table
            db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    address TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'user'))
                );
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
            `);

            // Stores table
            db.run(`
                CREATE TABLE IF NOT EXISTS stores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    address TEXT NOT NULL,
                    owner_id INTEGER,
                    FOREIGN KEY(owner_id) REFERENCES users(id)
                );
                CREATE INDEX IF NOT EXISTS idx_stores_name ON stores(name);
                CREATE INDEX IF NOT EXISTS idx_stores_email ON stores(email);
                CREATE INDEX IF NOT EXISTS idx_stores_owner ON stores(owner_id);
            `);

            // Ratings table
            db.run(`
                CREATE TABLE IF NOT EXISTS ratings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    store_id INTEGER NOT NULL,
                    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(store_id) REFERENCES stores(id),
                    UNIQUE(user_id, store_id)
                );
                CREATE INDEX IF NOT EXISTS idx_ratings_user ON ratings(user_id);
                CREATE INDEX IF NOT EXISTS idx_ratings_store ON ratings(store_id);
            `);
        });
        console.log('Connected to the SQLite database and initialized schema.');
    }
});

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format
    
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
    
    try {
        const decoded = jwt.verify(token, 'secretkey');
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ message: 'Invalid or expired token' });
    }
};

// Role-based authorization middleware
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                message: 'Access denied. Insufficient permissions.' 
            });
        }
        next();
    };
};

// Enhanced validation middleware
const validateRegistration = [
    body("name")
        .isLength({ min: 3 })
        .withMessage("Name must be at least 3 characters long")
        .trim()
        .escape(),
    body("email")
        .isEmail()
        .withMessage("Invalid email format")
        .normalizeEmail(),
    body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters long")
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
        .withMessage("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"),
    body("address")
        .isLength({ min: 5 })
        .withMessage("Address must be at least 5 characters long")
        .trim(),
    body("role")
        .isIn(['admin', 'owner', 'user'])
        .withMessage("Invalid role specified"),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

// User Registration
app.post('/register', validateRegistration, async (req, res) => {
    const { name, email, password, address, role } = req.body;
    
    try {
        // Check if email already exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({
                    message: 'Database error',
                    error: err.message
                });
            }
            
            if (user) {
                return res.status(400).json({
                    message: 'Registration failed',
                    error: 'Email already registered'
                });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 12);

            // Insert new user
            db.run(
                'INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)',
                [name, email, hashedPassword, address, role],
                function(err) {
                    if (err) {
                        return res.status(500).json({
                            message: 'Error creating user',
                            error: err.message
                        });
                    }

                    res.status(201).json({
                        message: 'User registered successfully',
                        userId: this.lastID
                    });
                }
            );
        });
    } catch (err) { 
        res.status(500).json({
            message: 'Server error during registration',
            error: err.message
        });
    }
});

// Enhanced login validation
const validateLogin = [
    body("email")
        .isEmail()
        .withMessage("Invalid email format")
        .normalizeEmail(),
    body("password")
        .notEmpty()
        .withMessage("Password is required"),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

// User Login
app.post('/login', validateLogin, async (req, res) => {
    const { email, password } = req.body;
    try {
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) return res.status(500).json({ message: 'Internal server error', error: err.message });
            
            if (!user) {
                return res.status(401).json({ 
                    message: 'Authentication failed', 
                    error: 'User not found with this email' 
                });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ 
                    message: 'Authentication failed', 
                    error: 'Invalid password' 
                });
            }

            // Create token with expiration
            const token = jwt.sign(
                { 
                    id: user.id, 
                    role: user.role,
                    email: user.email
                }, 
                'secretkey',
                { expiresIn: '1h' }  // Token expires in 1 hour
            );

            // Send response with user details (excluding password)
            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error during login',
            error: err.message
        });
    }
});

// List all stores
app.get('/stores', async (req, res) => {
    try {
        db.all('SELECT * FROM stores', [], (err, rows) => {
            if (err) return res.status(500).json(err);
            res.json(rows);
        });
    } catch (err) {
        res.status(500).json(err);
    }
});

// Admin Endpoints

// Add new store (Admin & Owner only)
app.post('/stores', authenticateToken, authorize('admin', 'owner'), [
    body('name').isLength({ min: 3 }).withMessage('Store name must be at least 3 characters long'),
    body('email').isEmail().withMessage('Invalid store email format'),
    body('address').isLength({ min: 5 }).withMessage('Store address must be at least 5 characters long'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, address } = req.body;
    const owner_id = req.user.role === 'owner' ? req.user.id : null;

    try {
        db.run(
            'INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)',
            [name, email, address, owner_id],
            function(err) {
                if (err) {
                    return res.status(500).json({
                        message: 'Error creating store',
                        error: err.message
                    });
                }
                res.status(201).json({
                    message: 'Store created successfully',
                    storeId: this.lastID
                });
            }
        );
    } catch (err) {
        res.status(500).json({
            message: 'Server error creating store',
            error: err.message
        });
    }
});

// Get system statistics (Admin only)
app.get('/stats', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        db.all(`
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM stores) as total_stores,
                (SELECT COUNT(*) FROM ratings) as total_ratings,
                (SELECT COUNT(*) FROM users WHERE role = 'admin') as total_admins,
                (SELECT COUNT(*) FROM users WHERE role = 'owner') as total_owners,
                (SELECT COUNT(*) FROM users WHERE role = 'user') as total_normal_users
        `, [], (err, rows) => {
            if (err) {
                return res.status(500).json({
                    message: 'Error fetching statistics',
                    error: err.message
                });
            }
            res.json(rows[0]);
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error fetching statistics',
            error: err.message
        });
    }
});

// List all users (Admin only)
app.get('/users', authenticateToken, authorize('admin'), async (req, res) => {
    const { role, search } = req.query;
    let query = 'SELECT id, name, email, role, address FROM users';
    const params = [];

    if (role) {
        query += ' WHERE role = ?';
        params.push(role);
    }

    if (search) {
        query += role ? ' AND' : ' WHERE';
        query += ' (name LIKE ? OR email LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    try {
        db.all(query, params, (err, rows) => {
            if (err) {
                return res.status(500).json({
                    message: 'Error fetching users',
                    error: err.message
                });
            }
            res.json(rows);
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error fetching users',
            error: err.message
        });
    }
});

// Store Rating Endpoints

// Submit or update rating
app.post('/ratings', authenticateToken, authorize('user'), [
    body('store_id').isInt().withMessage('Valid store ID is required'),
    body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { store_id, rating } = req.body;
    const user_id = req.user.id;

    try {
        // Check if store exists
        db.get('SELECT id FROM stores WHERE id = ?', [store_id], (err, store) => {
            if (err || !store) {
                return res.status(404).json({
                    message: 'Store not found'
                });
            }

            // Upsert rating
            db.run(`
                INSERT INTO ratings (user_id, store_id, rating)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, store_id) 
                DO UPDATE SET rating = ?, updated_at = CURRENT_TIMESTAMP
            `, [user_id, store_id, rating, rating], function(err) {
                if (err) {
                    return res.status(500).json({
                        message: 'Error submitting rating',
                        error: err.message
                    });
                }
                res.json({
                    message: 'Rating submitted successfully'
                });
            });
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error submitting rating',
            error: err.message
        });
    }
});

// Get store ratings (Store Owner & Admin)
app.get('/stores/:id/ratings', authenticateToken, authorize('admin', 'owner'), async (req, res) => {
    const { id } = req.params;

    // If owner, verify store ownership
    if (req.user.role === 'owner') {
        const store = await new Promise((resolve, reject) => {
            db.get('SELECT owner_id FROM stores WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (!store || store.owner_id !== req.user.id) {
            return res.status(403).json({
                message: 'Access denied. You can only view ratings for your own store.'
            });
        }
    }

    try {
        db.all(`
            SELECT 
                r.rating,
                r.created_at,
                r.updated_at,
                u.name as user_name,
                u.email as user_email
            FROM ratings r
            JOIN users u ON r.user_id = u.id
            WHERE r.store_id = ?
            ORDER BY r.updated_at DESC
        `, [id], (err, rows) => {
            if (err) {
                return res.status(500).json({
                    message: 'Error fetching ratings',
                    error: err.message
                });
            }

            // Calculate average rating
            const average = rows.reduce((acc, curr) => acc + curr.rating, 0) / (rows.length || 1);

            res.json({
                average_rating: parseFloat(average.toFixed(2)),
                total_ratings: rows.length,
                ratings: rows
            });
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error fetching ratings',
            error: err.message
        });
    }
});

// Search stores
app.get('/stores/search', authenticateToken, async (req, res) => {
    const { name, address } = req.query;
    let query = 'SELECT * FROM stores WHERE 1=1';
    const params = [];

    if (name) {
        query += ' AND name LIKE ?';
        params.push(`%${name}%`);
    }

    if (address) {
        query += ' AND address LIKE ?';
        params.push(`%${address}%`);
    }

    try {
        db.all(query, params, (err, rows) => {
            if (err) {
                return res.status(500).json({
                    message: 'Error searching stores',
                    error: err.message
                });
            }
            res.json(rows);
        });
    } catch (err) {
        res.status(500).json({
            message: 'Server error searching stores',
            error: err.message
        });
    }
});

// Initialize sample stores (Development purpose only)
app.post('/init-sample-stores', async (req, res) => {
    const sampleStores = [
        {
            name: 'Grocery Express',
            email: 'grocery@express.com',
            address: '123 Main Street, Downtown',
            owner_id: null
        },
        {
            name: 'Fashion Hub',
            email: 'info@fashionhub.com',
            address: '456 Style Avenue, Mall District',
            owner_id: null
        },
        {
            name: 'Tech World',
            email: 'contact@techworld.com',
            address: '789 Digital Road, Tech Park',
            owner_id: null
        },
        {
            name: 'Fresh Foods Market',
            email: 'hello@freshfoods.com',
            address: '321 Organic Lane, Green Zone',
            owner_id: null
        },
        {
            name: 'Sports Elite',
            email: 'info@sportselite.com',
            address: '555 Fitness Boulevard, Stadium Area',
            owner_id: null
        }
    ];

    try {
        // Use a transaction to ensure all stores are added or none
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');

            const stmt = db.prepare('INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)');
            
            sampleStores.forEach((store) => {
                stmt.run([store.name, store.email, store.address, store.owner_id]);
            });

            stmt.finalize();

            db.run('COMMIT', (err) => {
                if (err) {
                    return res.status(500).json({
                        message: 'Error initializing sample stores',
                        error: err.message
                    });
                }
                res.json({
                    message: 'Sample stores initialized successfully',
                    count: sampleStores.length
                });
            });
        });
    } catch (err) {
        db.run('ROLLBACK');
        res.status(500).json({
            message: 'Server error initializing sample stores',
            error: err.message
        });
    }
});

// Start server
app.listen(5000, () => console.log('Server running on port 5000'));
