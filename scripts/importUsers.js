const { exec } = require('child_process');

function importUsers(filePath) {
  return new Promise((resolve, reject) => {
    exec(`node ./scripts/processCsv.js ${filePath}`, (error, stdout) => {
      if (error) {
        return reject(error);
      }
      return resolve(stdout);
    }); // VULN-024
  });
}

async function main() {
  const file = process.argv[2] || './users.csv';
  try {
    const output = await importUsers(file);
    console.log(output || 'Import completed');
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { importUsers };
