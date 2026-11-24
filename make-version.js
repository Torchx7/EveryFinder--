// Usage: node make-version.js renderer/index.html 2
// Prints the version.json to commit at the top of the repo, next to renderer/index.html.
// Line endings are normalised to LF first, exactly as the app does before checking.
const fs = require('fs'), crypto = require('crypto');
const [file, version] = process.argv.slice(2);
if (!file || !version) { console.error('Usage: node make-version.js <path to index.html> <version number>'); process.exit(1); }
const text = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
const sha = crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
console.log(JSON.stringify({ version: Number(version), sha256: sha }, null, 2));
