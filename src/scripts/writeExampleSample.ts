import * as fs from 'fs';
import * as path from 'path';
import { CveSqliteManager } from './saveToSqlite';

const OUTPUT_DIR = path.join(process.cwd(), 'cveJsons');
const SQLITE_DB_PATH = path.join(process.cwd(), 'cve_database.db');

async function writeExampleSampleFromDb(limit: number = 5): Promise<void> {
  if (!fs.existsSync(SQLITE_DB_PATH)) {
    throw new Error(`Database not found: ${SQLITE_DB_PATH}`);
  }

  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  console.log(`[example] Querying first ${limit} entries from DB: ${SQLITE_DB_PATH}`);
  const manager = new CveSqliteManager(SQLITE_DB_PATH);
  const entries = await manager.queryEntries({ limit });
  await manager.close();

  const exampleFilePath = path.join(OUTPUT_DIR, 'example.txt');
  const ws = fs.createWriteStream(exampleFilePath, { encoding: 'utf8' });
  for (const e of entries) {
    ws.write(JSON.stringify(e));
    ws.write('\n');
  }
  ws.end();

  await new Promise<void>((resolve, reject) => {
    ws.on('finish', () => {
      console.log(`[example] Wrote ${entries.length} rows to: ${exampleFilePath}`);
      resolve();
    });
    ws.on('error', reject);
  });
}

async function main(): Promise<void> {
  try {
    const limitArg = process.argv.find(a => a.startsWith('--limit='));
    const limit = limitArg ? parseInt(limitArg.substring('--limit='.length), 10) : undefined;
    await writeExampleSampleFromDb(limit ?? 5);
  } catch (err) {
    console.error('[example] Failed to write example sample from DB:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { writeExampleSampleFromDb };


