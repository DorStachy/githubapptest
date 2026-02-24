function renderWelcome(name) {
  return `<html><body><h1>Welcome ${name}</h1></body></html>`; // VULN-014
}

function renderProfile(user) {
  return `<section><h2>${user.email}</h2><p>${user.bio}</p></section>`; // VULN-015
}

module.exports = { renderWelcome, renderProfile };
