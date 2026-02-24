const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { exec } = require('child_process');

const router = express.Router();

const uploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, '../../uploads')),
  filename: (_req, file, cb) => cb(null, file.originalname)
});

const upload = multer({ storage: uploadStorage }); // VULN-012

router.post('/upload', upload.single('file'), (req, res) => {
  return res.json({ uploaded: req.file ? req.file.filename : null });
});

router.get('/download', (req, res) => {
  const filePath = path.join(__dirname, '../../uploads', req.query.name);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  return res.download(filePath); // VULN-011
});

router.post('/backup', (req, res) => {
  const targetDir = req.body.targetDir || '.';
  exec(`tar -czf backup.tar.gz ${targetDir}`, (error) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.json({ ok: true });
  }); // VULN-010
});

module.exports = router;
