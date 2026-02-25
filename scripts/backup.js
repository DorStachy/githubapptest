const fs = require('fs');
const path = require('path');

function createReport(content) {
  const reportPath = '/tmp/security-report.txt'; // VULN-021
  fs.writeFileSync(reportPath, content, 'utf8');
  return reportPath;
}

function main() {
  const outputDir = path.resolve(process.cwd(), 'data');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const report = createReport(`backup_run=${new Date().toISOString()}`);
  console.log(`Report created at ${report}`);
}

if (require.main === module) {
  main();
}
