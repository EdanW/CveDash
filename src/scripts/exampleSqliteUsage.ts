import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';
import { CveSqliteManager, saveTableEntriesToSqlite } from './saveToSqlite';
import * as path from 'path';

/**
 * Example script showing how to use SQLite directly with your CVE data
 */
async function exampleSqlitePipeline() {
  console.log('🔄 Starting CVE to SQLite pipeline example...\n');

  try {
    // Step 1: Extract entries from your JSON feed
    const jsonFilePath = path.resolve(process.cwd(), 'cveJsons', 'nvdcve-1.1-2023.json');
    console.log(`📁 Reading from: ${jsonFilePath}`);
    
    const entries = extractTableEntriesFromDataFeedFile(jsonFilePath);
    console.log(`📊 Extracted ${entries.length} table entries\n`);

    if (entries.length === 0) {
      console.log('⚠️  No entries found, skipping SQLite save');
      return;
    }

    // Step 2: Save to SQLite database
    const dbPath = path.resolve(process.cwd(), 'cve_database.db');
    console.log(`💾 Saving to SQLite database: ${dbPath}`);

    await saveTableEntriesToSqlite(entries, dbPath, {
      tableName: 'cve_entries',
      createBackup: true,
      batchSize: 1000,
      verbose: true
    });

    console.log('\n✅ Pipeline completed successfully!');
    console.log(`📈 Summary:`);
    console.log(`   - Entries processed: ${entries.length}`);
    console.log(`   - Database file: ${dbPath}`);
    console.log(`   - Table: cve_entries`);
    console.log(`   - Composite key: (id, metricVersion)`);

  } catch (error) {
    console.error('❌ Pipeline failed:', error);
    process.exit(1);
  }
}

/**
 * Example showing how to query the SQLite database
 */
async function exampleQueryDatabase() {
  console.log('🔍 Querying SQLite database...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    // Get database statistics
    console.log('📊 Database Statistics:');
    const stats = await manager.getStats();
    console.log(`   Total entries: ${stats.totalEntries}`);
    console.log(`   Entries by severity:`, stats.entriesBySeverity);
    console.log(`   Entries by metric version:`, stats.entriesByMetricVersion);
    console.log(`   Date range: ${stats.dateRange.earliest} to ${stats.dateRange.latest}\n`);

    // Query recent high-severity entries
    console.log('🔍 Recent HIGH severity entries:');
    const highSeverityEntries = await manager.queryEntries({
      severity: 'HIGH',
      limit: 5
    });

    highSeverityEntries.forEach((entry, index) => {
      console.log(`   ${index + 1}. ${entry.id} (${entry.metricVersion}) - Score: ${entry.baseScore}`);
      console.log(`      ${entry.description.substring(0, 80)}...`);
    });

    // Query entries with high CVSS scores
    console.log('\n🔍 Entries with CVSS score >= 8.0:');
    const highScoreEntries = await manager.queryEntries({
      minScore: 8.0,
      limit: 3
    });

    highScoreEntries.forEach((entry, index) => {
      console.log(`   ${index + 1}. ${entry.id} - ${entry.baseSeverity} (${entry.baseScore})`);
    });

  } catch (error) {
    console.error('❌ Query failed:', error);
  } finally {
    await manager.close();
  }
}

/**
 * Example showing how to process multiple files and save to SQLite
 */
async function exampleMultipleFilesToSqlite() {
  console.log('🔄 Processing multiple CVE files to SQLite...\n');

  const fs = require('fs');
  const cveJsonsDir = path.resolve(process.cwd(), 'cveJsons');
  
  if (!fs.existsSync(cveJsonsDir)) {
    console.error(`❌ Directory not found: ${cveJsonsDir}`);
    return;
  }

  const jsonFiles = fs.readdirSync(cveJsonsDir)
    .filter((f: string) => f.toLowerCase().endsWith('.json'))
    .map((f: string) => path.join(cveJsonsDir, f));

  if (jsonFiles.length === 0) {
    console.log('⚠️  No JSON files found in cveJsons directory');
    return;
  }

  console.log(`📁 Found ${jsonFiles.length} JSON files to process`);

  const allEntries: any[] = [];
  
  for (const file of jsonFiles) {
    console.log(`\n📄 Processing: ${path.basename(file)}`);
    const entries = extractTableEntriesFromDataFeedFile(file);
    allEntries.push(...entries);
    console.log(`   ✅ Extracted ${entries.length} entries`);
  }

  console.log(`\n📊 Total entries across all files: ${allEntries.length}`);

  if (allEntries.length > 0) {
    const dbPath = path.resolve(process.cwd(), 'cve_database_combined.db');
    console.log(`\n💾 Saving all entries to SQLite: ${dbPath}`);

    await saveTableEntriesToSqlite(allEntries, dbPath, {
      tableName: 'cve_entries',
      createBackup: true,
      batchSize: 2000,
      verbose: true
    });

    console.log('\n✅ All files processed successfully!');
    
    // Show some stats
    const manager = new CveSqliteManager(dbPath);
    try {
      const stats = await manager.getStats();
      console.log(`\n📊 Final database stats:`);
      console.log(`   Total entries: ${stats.totalEntries}`);
      console.log(`   Severity breakdown:`, stats.entriesBySeverity);
    } finally {
      await manager.close();
    }
  }
}

/**
 * Example showing how to use the SQLite database in a simple web app
 */
async function exampleWebAppIntegration() {
  console.log('🌐 Example: Using SQLite database in a web app...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    // Simulate API endpoints
    console.log('📡 Simulating API endpoints:');
    
    // GET /api/cves?severity=HIGH&limit=10
    console.log('\n🔍 GET /api/cves?severity=HIGH&limit=10');
    const highSeverityCves = await manager.queryEntries({
      severity: 'HIGH',
      limit: 10
    });
    console.log(`   Found ${highSeverityCves.length} HIGH severity CVEs`);

    // GET /api/cves?minScore=9.0
    console.log('\n🔍 GET /api/cves?minScore=9.0');
    const criticalCves = await manager.queryEntries({
      minScore: 9.0,
      limit: 5
    });
    console.log(`   Found ${criticalCves.length} critical CVEs (score >= 9.0)`);

    // GET /api/stats
    console.log('\n📊 GET /api/stats');
    const stats = await manager.getStats();
    console.log(`   Database contains ${stats.totalEntries} total entries`);

  } catch (error) {
    console.error('❌ Web app simulation failed:', error);
  } finally {
    await manager.close();
  }
}

// Run examples based on command line arguments
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.includes('--query')) {
    exampleQueryDatabase().catch(console.error);
  } else if (args.includes('--multiple')) {
    exampleMultipleFilesToSqlite().catch(console.error);
  } else if (args.includes('--web')) {
    exampleWebAppIntegration().catch(console.error);
  } else {
    exampleSqlitePipeline().catch(console.error);
  }
}

export { 
  exampleSqlitePipeline, 
  exampleQueryDatabase, 
  exampleMultipleFilesToSqlite,
  exampleWebAppIntegration 
};
