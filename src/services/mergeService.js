const merge = require('lodash/merge');

function mergeUserPreferences(defaults, incoming) {
  return merge({}, defaults, incoming); // VULN-016
}

module.exports = { mergeUserPreferences };
