/**
 * User controller — INTENTIONALLY VULNERABLE for CodeFence testing.
 *
 * Covers: SQL injection, XSS, SSRF, path traversal, insecure deserialization,
 *         open redirect, prototype pollution, regex DoS, mass assignment.
 */

const express = require('express');
const mysql = require('mysql2');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const serialize = require('node-serialize');

const router = express.Router();
const db = mysql.createConnection({
  host: 'db.internal',
  user: 'root',
  password: 'supersecret123!',     // CRITICAL: hardcoded DB password
  database: 'userdb',
});

// ─────────────────────── SQL INJECTION (CRITICAL) ───────────────────────
router.get('/users', (req, res) => {
  const sort = req.query.sort || 'id';
  // Direct string interpolation — classic SQLi
  db.query(`SELECT * FROM users ORDER BY ${sort}`, (err, rows) => {
    if (err) return res.status(500).send(err.message);    // leaks internal error
    res.json(rows);
  });
});

router.get('/users/:id', (req, res) => {
  // Parameterised — this is SAFE, should NOT flag
  db.query('SELECT * FROM users WHERE id = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'query failed' });
    res.json(rows[0]);
  });
});

// ─────────────────────── SECOND ORDER SQL INJECTION (HIGH) ──────────────
router.post('/users/search', (req, res) => {
  const filters = req.body.filters; // user-controlled JSON
  let where = '1=1';
  for (const [col, val] of Object.entries(filters)) {
    where += ` AND ${col} = '${val}'`;   // column AND value injected
  }
  db.query(`SELECT * FROM users WHERE ${where}`, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// ─────────────────────── XSS — REFLECTED (HIGH) ────────────────────────
router.get('/greet', (req, res) => {
  const name = req.query.name;
  // Directly injected into HTML — reflected XSS
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

// ─────────────────────── XSS — SAFE (no vuln) ─────────────────────────
router.get('/greet-safe', (req, res) => {
  const name = escapeHtml(req.query.name || '');
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────── SSRF (CRITICAL) ───────────────────────────────
router.get('/fetch-url', async (req, res) => {
  const target = req.query.url;
  // No URL validation — attacker can hit internal metadata endpoints
  try {
    const response = await axios.get(target);
    res.json(response.data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ─────────────────────── SSRF — SAFE (allowlist) ───────────────────────
router.get('/fetch-safe', async (req, res) => {
  const allowedHosts = ['api.github.com', 'registry.npmjs.org'];
  const target = new URL(req.query.url);
  if (!allowedHosts.includes(target.hostname)) {
    return res.status(403).json({ error: 'host not allowed' });
  }
  const response = await axios.get(target.href);
  res.json(response.data);
});

// ─────────────────────── PATH TRAVERSAL (HIGH) ─────────────────────────
router.get('/file', (req, res) => {
  const filePath = req.query.name;
  // No sanitisation — ../../etc/passwd
  const fullPath = path.join('/uploads', filePath);
  fs.readFile(fullPath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});

// ─────────────────────── PATH TRAVERSAL — SAFE ─────────────────────────
router.get('/file-safe', (req, res) => {
  const filePath = path.basename(req.query.name); // strips directory components
  const fullPath = path.join('/uploads', filePath);
  if (!fullPath.startsWith('/uploads/')) {
    return res.status(400).send('invalid path');
  }
  fs.readFile(fullPath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});

// ─────────────────────── INSECURE DESERIALIZATION (CRITICAL) ────────────
router.post('/import', (req, res) => {
  // node-serialize.unserialize can execute arbitrary code
  const obj = serialize.unserialize(req.body.payload);
  res.json({ imported: obj });
});

// ─────────────────────── OPEN REDIRECT (MEDIUM) ────────────────────────
router.get('/redirect', (req, res) => {
  const next = req.query.next;
  // Attacker controls redirect destination
  res.redirect(next);
});

// ─────────────────────── OPEN REDIRECT — SAFE ──────────────────────────
router.get('/redirect-safe', (req, res) => {
  const next = req.query.next;
  if (!next || !next.startsWith('/')) {
    return res.redirect('/');
  }
  res.redirect(next);
});

// ─────────────────────── PROTOTYPE POLLUTION (HIGH) ─────────────────────
router.post('/settings', (req, res) => {
  const defaults = { theme: 'light', lang: 'en' };
  // Deep merge with user input — __proto__ key pollutes Object prototype
  deepMerge(defaults, req.body);
  res.json(defaults);
});

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ─────────────────────── REGEX DOS (MEDIUM) ─────────────────────────────
router.post('/validate-email', (req, res) => {
  // Evil regex — catastrophic backtracking on long input
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z]{2,4})+$/;
  const valid = emailRegex.test(req.body.email);
  res.json({ valid });
});

// ─────────────────────── MASS ASSIGNMENT (MEDIUM) ───────────────────────
router.put('/users/:id', (req, res) => {
  // Spreads entire req.body into UPDATE — attacker can set isAdmin=true
  const fields = Object.entries(req.body)
    .map(([k, v]) => `${k} = '${v}'`)               // also SQLi!
    .join(', ');
  db.query(`UPDATE users SET ${fields} WHERE id = ${req.params.id}`, (err) => {
    if (err) return res.status(500).send(err.message);
    res.json({ ok: true });
  });
});

module.exports = router;
