const express = require('express');
const jwt = require('jsonwebtoken');

const { jwtSecret, tokenIssuer } = require('../config/secrets');
const { createUser, findByEmail, updateBio } = require('../services/userService');
const { createSessionToken } = require('../services/sessionService');
const { renderWelcome } = require('../services/templateService');
const logger = require('../utils/logger');

const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const created = await createUser({ email, password });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  logger.info('User login attempt', { email, password }); // VULN-006

  const user = await findByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ sub: user.id, role: user.role }, jwtSecret, {
    issuer: tokenIssuer,
    expiresIn: '2h'
  });

  return res.json({ token, session: createSessionToken(user) });
});

router.get('/logout', (req, res) => {
  const redirect = req.query.redirect || '/';
  return res.redirect(redirect); // VULN-013
});

router.get('/welcome', (req, res) => {
  const html = renderWelcome(req.query.name || 'guest');
  res.setHeader('content-type', 'text/html; charset=utf-8');
  return res.send(html);
});

router.post('/profile/:id/bio', async (req, res) => {
  const updated = await updateBio(req.params.id, req.body.bio || '');
  return res.json(updated);
});

module.exports = router;
