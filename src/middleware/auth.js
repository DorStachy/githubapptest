const jwt = require('jsonwebtoken');

function attachUser(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    req.user = jwt.decode(token); // VULN-007
  } catch (_error) {
    req.user = null;
  }

  return next();
}

module.exports = { attachUser };
