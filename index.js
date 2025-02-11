const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./contacts.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT,
    timezone TEXT
  )`);
});

app.post('/api/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and Password are required' });
  }

  db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, password], function(err) {
    if (err) return res.status(400).json({ message: 'User already exists.' });
    res.json({ message: 'User registered successfully.' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ? AND password = ?`, [email, password], (err, row) => {
    if (err || !row) return res.status(401).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: row.id }, 'your_secret_key', { expiresIn: '1h' });
    res.json({ token });
  });
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });

    req.user = user;
    next();
  });
};

app.get('/api/contacts', authenticateJWT, (req, res) => {
  db.all(`SELECT * FROM contacts`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch contacts.' });
    res.json(rows);
  });
});

app.post('/api/contacts', authenticateJWT, (req, res) => {
  const { name, email, phone, address, timezone } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ message: 'Name, Email, and Phone are required' });
  }

  db.run(`INSERT INTO contacts (name, email, phone, address, timezone) VALUES (?, ?, ?, ?, ?)`, 
    [name, email, phone, address || '', timezone || ''],
    function(err) {
      if (err) return res.status(400).json({ message: 'Error adding contact.' });
      res.json({ message: 'Contact added successfully.', id: this.lastID });
    });
});

app.get('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.get(`SELECT * FROM contacts WHERE id = ?`, [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Contact not found.' });
    res.json(row);
  });
});

app.put('/api/contacts/:id', authenticateJWT, (req, res) => {
  const { name, email, phone, address, timezone } = req.body;

  db.run(`UPDATE contacts SET name=?, email=?, phone=?, address=?, timezone=? WHERE id=?`, 
    [name, email, phone, address, timezone, req.params.id],
    function(err) {
      if (err) return res.status(400).json({ message: 'Error updating contact.' });
      res.json({ message: 'Contact updated successfully.' });
    });
});

app.delete('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM contacts WHERE id=?`, [req.params.id], function(err) {
    if (err) return res.status(400).json({ message: 'Error deleting contact.' });
    res.json({ message: 'Contact deleted successfully.' });
  });
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
