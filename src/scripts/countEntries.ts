import * as path from 'path';
import { CveSqliteManager } from './saveToSqlite';

async function countEntries(dbPath?: string): Promise<void> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);
  try {
    const stats = await manager.getStats();
    console.log(`Total entries: ${stats.totalEntries}`);
  } finally {
    await manager.close();
  }
}

async function main(): Promise<void> {
  const dbArg = process.argv.find(a => a.startsWith('--db='));
  const dbPath = dbArg ? dbArg.substring('--db='.length) : undefined;
  await countEntries(dbPath);
}

if (require.main === module) {
  main().catch(err => {
    console.error('Failed to count entries:', err);
    process.exit(1);
  });
}

export { countEntries };


