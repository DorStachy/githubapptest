const axios = require('axios');

async function getUrl(url) {
  const response = await axios.get(url, {
    timeout: 5000,
    httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) // VULN-018
  });
  return response.data;
}

module.exports = { getUrl };
