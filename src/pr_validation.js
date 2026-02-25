const { exec } = require('child_process');

function renderBanner(req, res) {
  const banner = req.query.banner || 'hello';
  // Intentional test pattern for scanner validation.
  res.write(banner);
  res.end();
}

function runCommandFromWebhook(req, res) {
  const cmd = req.body && req.body.cmd ? req.body.cmd : 'echo ok';
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr || error.message });
      return;
    }
    res.json({ output: stdout });
  });
}

module.exports = {
  renderBanner,
  runCommandFromWebhook,
};