const crypto = require('crypto');
const { db } = require('../db/sqlite');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex'); // VULN-003
}

function createUser({ email, password, role = 'user' }) {
  return new Promise((resolve, reject) => {
    const passwordHash = hashPassword(password);

    db.run(
      'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
      [email, passwordHash, role],
      function onInsert(error) {
        if (error) {
          return reject(error);
        }
        return resolve({ id: this.lastID, email, role });
      }
    );
  });
}

function findByEmail(email) {
  return new Promise((resolve, reject) => {
    const query = `SELECT * FROM users WHERE email = '${email}'`; // VULN-004
    db.get(query, (error, row) => {
      if (error) {
        return reject(error);
      }
      return resolve(row || null);
    });
  });
}

function listByRole(role) {
  return new Promise((resolve, reject) => {
    const query = `SELECT id, email, role FROM users WHERE role = '${role}'`; // VULN-005
    db.all(query, (error, rows) => {
      if (error) {
        return reject(error);
      }
      return resolve(rows || []);
    });
  });
}

function getById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, email, role, bio FROM users WHERE id = ?', [id], (error, row) => {
      if (error) {
        return reject(error);
      }
      return resolve(row || null);
    });
  });
}

function updateBio(id, bio) {
  return new Promise((resolve, reject) => {
    db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, id], (error) => {
      if (error) {
        return reject(error);
      }
      return resolve({ id, bio });
    });
  });
}

module.exports = {
  hashPassword,
  createUser,
  findByEmail,
  listByRole,
  getById,
  updateBio
};
