const express = require('express');
const cors = require('cors');

const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const fileRoutes = require('./routes/fileRoutes');
const integrationRoutes = require('./routes/integrationRoutes');

const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: '*',
    credentials: true
  })
);

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
app.use('/files', fileRoutes);
app.use('/integrations', integrationRoutes);

module.exports = app;
