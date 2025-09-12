import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';

const fs = require('fs');
const path = require('path');

function main() {
  const root = process.cwd();
  const folder = path.resolve(root, 'cveJsons');

  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    console.error(`cveJsons folder not found at ${folder}`);
    process.exit(1);
  }

  const files: string[] = fs
    .readdirSync(folder)
    .filter((f: string) => f.toLowerCase().endsWith('.json'))
    .map((f: string) => path.join(folder, f));

  if (files.length === 0) {
    console.warn('No JSON files found in cveJsons');
    process.exit(0);
  }

  const outPath = path.resolve(root, 'test_db.txt');
  const ws = fs.createWriteStream(outPath, { encoding: 'utf8' });

  let totalEntries = 0;
  for (const file of files) {
    console.log(`[folder] Processing: ${file}`);
    const entries = extractTableEntriesFromDataFeedFile(file);
    totalEntries += entries.length;
    for (const e of entries) {
      ws.write(JSON.stringify(e));
      ws.write('\n');
    }
  }

  ws.end();
  ws.on('finish', () => {
    console.log(`[folder] Done. Files: ${files.length}. Entries written: ${totalEntries}. Output: ${outPath}`);
  });
}

main();
