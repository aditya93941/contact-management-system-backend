const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

const DATABASE_FILE = './contacts.db';

// Initialize SQLite Database
const db = new sqlite3.Database(DATABASE_FILE, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
    initializeDatabase();
  }
});

// Function to Create Tables
function initializeDatabase() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,  
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )`
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS contacts (
        id TEXT PRIMARY KEY,  
        user_id TEXT NOT NULL, 
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        address TEXT
      )`
    );

    console.log('Database tables created (if not existing).');
  });
}

// Register a New User
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and Password are required' });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, existingUser) => {
    if (err) return res.status(500).json({ message: 'Database error.' });

    if (existingUser) return res.status(400).json({ message: 'User already exists.' });

    const userId = uuidv4();
    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        `INSERT INTO users (id, email, password) VALUES (?, ?, ?)`,
        [userId, email, hashedPassword],
        function (err) {
          if (err) return res.status(500).json({ message: 'Error registering user.' });
          res.json({ message: 'User registered successfully.' });
        }
      );
    } catch (err) {
      return res.status(500).json({ message: 'Error hashing password.' });
    }
  });
});

// Login Endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error.' });

    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ message: 'Error verifying password.' });

      if (!result) return res.status(401).json({ message: 'Invalid credentials.' });

      const token = jwt.sign({ id: user.id }, 'adithya', { expiresIn: '1h' });
      res.json({ token });
    });
  });
});

// Middleware to Authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, 'adithya', (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });

    req.user = user;
    next();
  });
};

// Get Contacts for Authenticated User
app.get('/api/contacts', authenticateJWT, (req, res) => {
  db.all(`SELECT * FROM contacts WHERE user_id = ?`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch contacts.' });
    res.json(rows);
  });
});

// Add a New Contact
app.post('/api/contacts', authenticateJWT, (req, res) => {
  const { name, email, phone, address } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ message: 'Name, Email, and Phone are required' });
  }

  const contactId = uuidv4();
  db.run(
    `INSERT INTO contacts (id, user_id, name, email, phone, address) VALUES (?, ?, ?, ?, ?, ?)`,
    [contactId, req.user.id, name, email, phone, address || ''],
    function (err) {
      if (err) return res.status(400).json({ message: 'Error adding contact.' });
      res.json({ message: 'Contact added successfully.', id: contactId });
    }
  );
});

// Get a Specific Contact by ID
app.get('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.get(`SELECT * FROM contacts WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Contact not found.' });
    res.json(row);
  });
});

// Update a Contact
app.put('/api/contacts/:id', authenticateJWT, (req, res) => {
  const { name, email, phone, address } = req.body;

  db.run(
    `UPDATE contacts SET name=?, email=?, phone=?, address=? WHERE id=? AND user_id=?`,
    [name, email, phone, address, req.params.id, req.user.id],
    function (err) {
      if (err) return res.status(400).json({ message: 'Error updating contact.' });
      res.json({ message: 'Contact updated successfully.' });
    }
  );
});

// Delete a Contact
app.delete('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM contacts WHERE id=? AND user_id=?`, [req.params.id, req.user.id], function (err) {
    if (err) return res.status(400).json({ message: 'Error deleting contact.' });
    res.json({ message: 'Contact deleted successfully.' });
  });
});

// Clear All Contacts for a User
app.post('/api/clear-contacts', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM contacts WHERE user_id = ?`, [req.user.id], function (err) {
    if (err) return res.status(500).json({ message: 'Failed to clear contacts.' });
    res.json({ message: 'User contacts cleared successfully.' });
  });
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
