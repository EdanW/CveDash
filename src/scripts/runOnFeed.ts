import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';

const fs = require('fs');
const path = require('path');

function main() {
  const feedPath = process.argv[2];
  if (!feedPath) {
    console.error('Usage: ts-node src/scripts/runOnFeed.ts <path-to-nvd-feed.json>');
    process.exit(1);
  }

  const abs = path.resolve(feedPath);
  const entries = extractTableEntriesFromDataFeedFile(abs);

  const outPath = path.resolve(process.cwd(), 'test_db.txt');
  const ws = fs.createWriteStream(outPath, { encoding: 'utf8' });
  for (const e of entries) {
    ws.write(JSON.stringify(e));
    ws.write('\n');
  }
  ws.end();

  ws.on('finish', () => {
    console.log(`Wrote ${entries.length} entries to ${outPath}`);
  });
}

main();
