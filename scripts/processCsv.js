const fs = require('fs');

function processCsv(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error('CSV file does not exist');
  }

  const data = fs.readFileSync(filePath, 'utf8');
  const lines = data.split('\n').filter(Boolean);
  return `Processed ${lines.length} rows`;
}

if (require.main === module) {
  const filePath = process.argv[2];
  const result = processCsv(filePath);
  console.log(result);
}

module.exports = { processCsv };
