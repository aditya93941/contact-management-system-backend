const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./contacts.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

//initialize Tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,  
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,  
    user_id TEXT NOT NULL, 
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT
  )`);
});

//register User
app.post('/api/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and Password are required' });
  }

  const userId = uuidv4(); //generate UUID for user
  db.run(`INSERT INTO users (id, email, password) VALUES (?, ?, ?)`, [userId, email, password], function(err) {
    if (err) return res.status(400).json({ message: 'User already exists.' });
    res.json({ message: 'User registered successfully.' });
  });
});

//Login User
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ? AND password = ?`, [email, password], (err, user) => {
    if (err || !user) return res.status(401).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id }, 'your_secret_key', { expiresIn: '1h' });
    res.json({ token });
  });
});

//Middleware: Authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });

    req.user = user;
    next();
  });
};

//Get Contacts (Only User's Contacts)
app.get('/api/contacts', authenticateJWT, (req, res) => {
  db.all(`SELECT * FROM contacts WHERE user_id = ?`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch contacts.' });
    res.json(rows);
  });
});

//Add Contact (Only for Logged-in User)
app.post('/api/contacts', authenticateJWT, (req, res) => {
  const { name, email, phone, address } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ message: 'Name, Email, and Phone are required' });
  }

  const contactId = uuidv4(); //Generate UUID for contact
  db.run(`INSERT INTO contacts (id, user_id, name, email, phone, address) VALUES (?, ?, ?, ?, ?, ?)`, 
    [contactId, req.user.id, name, email, phone, address || ''], 
    function(err) {
      if (err) return res.status(400).json({ message: 'Error adding contact.' });
      res.json({ message: 'Contact added successfully.', id: contactId });
    });
});

//Get Single Contact (Only User's Contact)
app.get('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.get(`SELECT * FROM contacts WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err, row) => {
    if (err || !row) return res.status(404).json({ message: 'Contact not found.' });
    res.json(row);
  });
});

//Update Contact (Only User's Contact)
app.put('/api/contacts/:id', authenticateJWT, (req, res) => {
  const { name, email, phone, address } = req.body;

  db.run(`UPDATE contacts SET name=?, email=?, phone=?, address=? WHERE id=? AND user_id=?`, 
    [name, email, phone, address, req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(400).json({ message: 'Error updating contact.' });
      res.json({ message: 'Contact updated successfully.' });
    });
});

//Delete Contact (Only User's Contact)
app.delete('/api/contacts/:id', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM contacts WHERE id=? AND user_id=?`, [req.params.id, req.user.id], function(err) {
    if (err) return res.status(400).json({ message: 'Error deleting contact.' });
    res.json({ message: 'Contact deleted successfully.' });
  });
});

//Clear User's Contacts (if needed)
app.post('/api/clear-contacts', authenticateJWT, (req, res) => {
  db.run(`DELETE FROM contacts WHERE user_id = ?`, [req.user.id], function(err) {
    if (err) return res.status(500).json({ message: 'Failed to clear contacts.' });
    res.json({ message: 'User contacts cleared successfully.' });
  });
});

//Start Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
