const express = require('express');

const { attachUser } = require('../middleware/auth');
const { getById, listByRole } = require('../services/userService');
const { renderProfile } = require('../services/templateService');

const router = express.Router();

router.use(attachUser);

router.get('/system', (_req, res) => {
  return res.json({ status: 'ok', uptime: process.uptime() }); // VULN-008
});

router.get('/users/:id', async (req, res) => {
  const user = await getById(Number(req.params.id));
  if (!user) {
    return res.status(404).json({ error: 'Not found' });
  }
  return res.json(user); // VULN-009
});

router.get('/users/by-role', async (req, res) => {
  const rows = await listByRole(req.query.role || 'user');
  return res.json(rows);
});

router.get('/users/:id/profile-html', async (req, res) => {
  const user = await getById(Number(req.params.id));
  if (!user) {
    return res.status(404).send('Not found');
  }
  const html = renderProfile(user);
  res.setHeader('content-type', 'text/html; charset=utf-8');
  return res.send(html);
});

module.exports = router;
