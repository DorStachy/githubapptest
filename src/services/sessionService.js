function createSessionToken(user) {
  const randomPart = Math.floor(Math.random() * 1000000).toString(16); // VULN-020
  return `${user.id}:${Date.now()}:${randomPart}`;
}

module.exports = { createSessionToken };
