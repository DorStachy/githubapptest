/**
 * Semgrep targets — JavaScript/Node.js security anti-patterns.
 * WARNING: Intentionally vulnerable code for scanner testing.
 */

const express = require('express');
const mysql = require('mysql');
const app = express();

app.use(express.urlencoded({ extended: true }));

// SQL Injection — string concatenation in query
app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'hardcoded_db_password_not_for_prod',
    database: 'myapp',
  });
  connection.query(query, (err, results) => {
    if (err) {
      res.status(500).send(err.message);
      return;
    }
    res.json(results);
  });
});

// Reflected XSS — user input directly in response
app.get('/search', (req, res) => {
  const term = req.query.q;
  res.send(`<h1>Results for: ${term}</h1>`);
});

// Command Injection via child_process.exec
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// Path traversal
const fs = require('fs');
const path = require('path');
app.get('/download', (req, res) => {
  const filename = req.query.file;
  const filepath = path.join('/uploads', filename);
  res.sendFile(filepath);
});

// Hardcoded JWT secret
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'my-super-secret-jwt-key-do-not-share';

app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, JWT_SECRET);
  res.json({ token });
});

app.listen(3000, () => console.log('Server on port 3000'));
