const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { exec, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const { MongoClient } = require('mongodb');
const ldap = require('ldapjs');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
  db.run("INSERT INTO users (username,password) VALUES ('admin','admin123')");
});

const JWT_SECRET = 'hardcoded-jwt-secret-value';
const MONGO_URI = 'mongodb://admin:admin@localhost:27017/test';
const LDAP_URL = 'ldap://localhost:389';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

app.get('/login', (req, res) => {
  const query = "SELECT * FROM users WHERE username='" + req.query.username + "' AND password='" + req.query.password + "'";
  db.get(query, [], (err, row) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    res.json({ ok: !!row, user: row || null });
  });
});

app.get('/run', (req, res) => {
  exec(req.query.cmd, (err, stdout, stderr) => {
    res.send(err ? stderr : stdout);
  });
});

app.get('/run-sync', (req, res) => {
  const output = execSync(req.query.cmd2 || 'echo default').toString();
  res.send(output);
});

app.get('/file', (req, res) => {
  const target = path.join(__dirname, req.query.name);
  res.sendFile(target);
});

app.get('/goto', (req, res) => {
  res.redirect(req.query.next || '/');
});

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body>Search results for: ${q}</body></html>`);
});

app.post('/execute-rule', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

app.post('/merge-profile', (req, res) => {
  const defaults = { theme: 'light', role: 'user' };
  const merged = Object.assign(defaults, req.body);
  res.json(merged);
});

app.post('/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.value || '').digest('hex');
  res.json({ hash });
});

app.post('/encrypt', (req, res) => {
  const key = crypto.randomBytes(24);
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  let encrypted = cipher.update(req.body.value || '', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

app.get('/token', (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.json({ token });
});

app.get('/session', (req, res) => {
  const token = jwt.sign({ user: req.query.user || 'guest' }, JWT_SECRET, { expiresIn: '7d' });
  res.setHeader('Set-Cookie', `session=${token}; Path=/`);
  res.json({ token });
});

app.get('/transfer-funds', (req, res) => {
  res.json({ status: 'ok', from: req.query.from, to: req.query.to, amount: req.query.amount });
});

app.get('/fetch-url', async (req, res) => {
  try {
    const response = await axios.get(req.query.url);
    res.send(response.data);
  } catch (e) {
    res.status(500).send(String(e));
  }
});

app.post('/mongo-login', async (req, res) => {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const doc = await client.db('test').collection('users').findOne(req.body);
  await client.close();
  res.json({ ok: !!doc, doc });
});

app.get('/ldap-search', (req, res) => {
  const client = ldap.createClient({ url: LDAP_URL });
  const opts = {
    filter: `(&(uid=${req.query.user})(objectClass=person))`,
    scope: 'sub'
  };
  client.search('ou=users,dc=example,dc=com', opts, (err, ldapRes) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    const entries = [];
    ldapRes.on('searchEntry', (entry) => entries.push(entry.object));
    ldapRes.on('end', () => res.json(entries));
  });
});

app.get('/tls-proxy', (req, res) => {
  const agent = new https.Agent({ rejectUnauthorized: false });
  https
    .get(req.query.endpoint, { agent }, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => (data += chunk));
      proxyRes.on('end', () => res.send(data));
    })
    .on('error', (err) => res.status(500).send(err.message));
});

app.post('/save-script', (req, res) => {
  const filePath = '/tmp/' + req.body.filename;
  fs.writeFileSync(filePath, req.body.content || '');
  res.json({ saved: filePath });
});

app.get('/config', (_req, res) => {
  res.json({
    env: process.env.NODE_ENV || 'dev',
    awsAccessKeyId: AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: AWS_SECRET_ACCESS_KEY,
    jwtSecret: JWT_SECRET,
    dbPassword: 'postgres123'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable demo app listening on ${PORT}`);
});
