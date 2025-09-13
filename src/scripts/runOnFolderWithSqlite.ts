import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';
import { saveTableEntriesToSqlite } from './saveToSqlite';

const fs = require('fs');
const path = require('path');

/**
 * Modified version of runOnFolder.ts that saves to SQLite database instead of text file
 * This creates a local .db file that you can use directly without importing
 */
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

  console.log(`📁 Found ${files.length} JSON files to process`);

  // Process all files and collect entries
  const allEntries: any[] = [];
  let totalEntries = 0;

  for (const file of files) {
    console.log(`[folder] Processing: ${path.basename(file)}`);
    const entries = extractTableEntriesFromDataFeedFile(file);
    allEntries.push(...entries);
    totalEntries += entries.length;
    console.log(`   ✅ Extracted ${entries.length} entries`);
  }

  console.log(`\n📊 Total entries collected: ${totalEntries}`);

  if (totalEntries === 0) {
    console.warn('No entries found, nothing to save');
    process.exit(0);
  }

  // Save to SQLite database
  const dbPath = path.resolve(root, 'cve_database.db');
  console.log(`\n💾 Saving to SQLite database: ${dbPath}`);

  saveTableEntriesToSqlite(allEntries, dbPath, {
    tableName: 'cve_entries',
    createBackup: true,
    batchSize: 1000,
    verbose: true
  }).then(() => {
    console.log(`\n✅ Successfully processed ${files.length} files and saved ${totalEntries} entries to SQLite`);
    console.log(`📄 Database file: ${dbPath}`);
    console.log(`🗃️  Table: cve_entries`);
    console.log(`🔑 Composite primary key: (id, metricVersion)`);
    console.log(`\n💡 You can now use this database file directly with any SQLite tool or library!`);
    console.log(`   - SQLite Browser: Open ${dbPath}`);
    console.log(`   - Command line: sqlite3 ${dbPath}`);
    console.log(`   - In your app: new sqlite3.Database('${dbPath}')`);
  }).catch((error) => {
    console.error('❌ Error saving to SQLite:', error);
    process.exit(1);
  });
}

main();
