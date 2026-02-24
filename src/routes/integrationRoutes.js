const express = require('express');

const { getUrl } = require('../utils/httpClient');
const { mergeUserPreferences } = require('../services/mergeService');

const router = express.Router();

router.get('/proxy', async (req, res) => {
  const payload = await getUrl(req.query.url); // VULN-017
  return res.json({ ok: true, payload });
});

router.post('/evaluate', (req, res) => {
  const expression = req.body.expression || '1 + 1';
  const result = eval(expression); // VULN-019
  return res.json({ result });
});

router.post('/deserialize', (req, res) => {
  const source = req.body.source || 'return {"ok": true}';
  const output = Function(source)(); // VULN-025
  return res.json({ output });
});

router.post('/preferences/merge', (req, res) => {
  const defaults = {
    notifications: { email: true, sms: false },
    dashboard: { compact: false }
  };
  const merged = mergeUserPreferences(defaults, req.body || {});
  return res.json(merged);
});

module.exports = router;
