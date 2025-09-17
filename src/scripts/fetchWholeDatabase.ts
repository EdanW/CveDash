import * as fs from 'fs';
import * as path from 'path';
import { fetchYearEntries } from './fetchYearEntries';
import { fetchModifiedCves } from './upsertModifiedEntries';

const SQLITE_DB_PATH = path.join(process.cwd(), 'cve_database.db');

async function fetchWholeDatabase(): Promise<void> {
  try {
    console.log('[whole] Starting full database fetch...');

    // 1) Delete the CVE database if it exists
    if (fs.existsSync(SQLITE_DB_PATH)) {
      console.log(`[whole] Deleting existing database: ${SQLITE_DB_PATH}`);
      fs.unlinkSync(SQLITE_DB_PATH);
    } else {
      console.log('[whole] No existing database found, continuing...');
    }

    // 2) For each year 2002-2025 insert entries (no upsert)
    for (let year = 2002; year <= 2025; year++) {
      console.log(`[whole] Processing year ${year}...`);
      await fetchYearEntries(year);
    }

    // 3) Upsert modified entries to bring DB current
    console.log('[whole] Fetching modified feed for upsert...');
    await fetchModifiedCves();

    console.log('[whole] Completed full database fetch successfully.');
  } catch (err) {
    console.error('[whole] Failed during full database fetch:', err);
    throw err;
  }
}

async function main(): Promise<void> {
  try {
    await fetchWholeDatabase();
  } catch (err) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { fetchWholeDatabase };


