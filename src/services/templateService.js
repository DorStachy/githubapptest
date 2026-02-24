const vm = require('vm');

function renderWelcome(name) {
  return `<html><body><h1>Welcome ${name}</h1></body></html>`; // VULN-014
}

function renderProfile(user) {
  return `<section><h2>${user.email}</h2><p>${user.bio}</p></section>`; // VULN-015
}

function renderUserSnippet(snippet, context) {
  return vm.runInNewContext('`' + snippet + '`', context); // VULN-026
}

module.exports = { renderWelcome, renderProfile, renderUserSnippet };
