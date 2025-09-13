# SQLite Integration for CVE Data

This directory contains SQLite integration for your CVE data processing pipeline. Unlike the SQL file generation, this creates actual SQLite database files (`.db`) that you can use directly in your local application.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Process Your CVE Data
```bash
# Process all JSON files in cveJsons folder and save to SQLite
npx ts-node src/scripts/runOnFolderWithSqlite.ts
```

This will create a `cve_database.db` file in your project root.

## 📁 Files Overview

### Core Files
- **`saveToSqlite.ts`** - Main SQLite manager class
- **`runOnFolderWithSqlite.ts`** - Drop-in replacement for your existing pipeline
- **`exampleSqliteUsage.ts`** - Comprehensive usage examples

### Key Features
- ✅ **Direct SQLite database creation** - No need to import SQL files
- ✅ **Composite primary key** - `(id, metricVersion)` handles multiple entries per CVE
- ✅ **Automatic table creation** - Creates tables and indexes automatically
- ✅ **Upsert functionality** - Updates existing entries, inserts new ones
- ✅ **Batch processing** - Handles large datasets efficiently
- ✅ **Backup creation** - Creates backups before updates
- ✅ **Query interface** - Built-in query methods for common operations

## 🗃️ Database Schema

The SQLite database contains a single table `cve_entries` with:

```sql
CREATE TABLE cve_entries (
    id TEXT NOT NULL,
    sourceIdentifier TEXT,
    published TEXT,
    lastModified TEXT,
    vulnStatus TEXT,
    description TEXT,
    metricVersion TEXT NOT NULL,
    source TEXT,
    baseScore REAL,
    vectorString TEXT,
    baseSeverity TEXT,
    attackVector TEXT,
    attackComplexity TEXT,
    exploitabilityScore REAL,
    impactScore REAL,
    cweIds TEXT, -- JSON string
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, metricVersion)
);
```

## 💻 Usage Examples

### Basic Usage
```typescript
import { saveTableEntriesToSqlite } from './saveToSqlite';
import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';

// Extract entries from JSON feed
const entries = extractTableEntriesFromDataFeedFile('path/to/feed.json');

// Save to SQLite database
await saveTableEntriesToSqlite(entries, './cve_database.db', {
  tableName: 'cve_entries',
  createBackup: true,
  batchSize: 1000,
  verbose: true
});
```

### Query the Database
```typescript
import { CveSqliteManager } from './saveToSqlite';

const manager = new CveSqliteManager('./cve_database.db');

// Get high severity entries
const highSeverityEntries = await manager.queryEntries({
  severity: 'HIGH',
  limit: 10
});

// Get entries with high CVSS scores
const criticalEntries = await manager.queryEntries({
  minScore: 9.0,
  limit: 5
});

// Get database statistics
const stats = await manager.getStats();
console.log(`Total entries: ${stats.totalEntries}`);

await manager.close();
```

## 🛠️ Available Scripts

### Process CVE Data
```bash
# Process all JSON files to SQLite
npx ts-node src/scripts/runOnFolderWithSqlite.ts
```

### Run Examples
```bash
# Basic pipeline example
npx ts-node src/scripts/exampleSqliteUsage.ts

# Query existing database
npx ts-node src/scripts/exampleSqliteUsage.ts --query

# Process multiple files
npx ts-node src/scripts/exampleSqliteUsage.ts --multiple

# Web app integration example
npx ts-node src/scripts/exampleSqliteUsage.ts --web
```

## 🔍 Using the Database File

Once created, you can use the `cve_database.db` file with:

### SQLite Browser (GUI)
- Download SQLite Browser
- Open `cve_database.db`
- Browse and query your CVE data

### Command Line
```bash
sqlite3 cve_database.db
.tables
SELECT COUNT(*) FROM cve_entries;
SELECT * FROM cve_entries WHERE baseSeverity = 'HIGH' LIMIT 5;
```

### In Your Application
```typescript
import * as sqlite3 from 'sqlite3';

const db = new sqlite3.Database('./cve_database.db');

db.all("SELECT * FROM cve_entries WHERE baseSeverity = ?", ['HIGH'], (err, rows) => {
  if (err) throw err;
  console.log(rows);
});

db.close();
```

## 📊 Query Examples

### Find High Severity CVEs
```sql
SELECT id, baseSeverity, baseScore, description 
FROM cve_entries 
WHERE baseSeverity = 'HIGH' 
ORDER BY baseScore DESC 
LIMIT 10;
```

### Find CVEs by Date Range
```sql
SELECT id, published, baseSeverity, baseScore 
FROM cve_entries 
WHERE published >= '2023-01-01' 
ORDER BY published DESC;
```

### Find CVEs by CWE
```sql
SELECT id, baseSeverity, cweIds 
FROM cve_entries 
WHERE cweIds LIKE '%CWE-79%';
```

### Get Statistics
```sql
SELECT 
  baseSeverity, 
  COUNT(*) as count,
  AVG(baseScore) as avg_score
FROM cve_entries 
GROUP BY baseSeverity 
ORDER BY count DESC;
```

## 🔧 Configuration Options

The `saveTableEntriesToSqlite` function accepts these options:

```typescript
{
  tableName?: string;        // Table name (default: 'cve_entries')
  createBackup?: boolean;    // Create backup before update (default: true)
  batchSize?: number;        // Batch size for processing (default: 1000)
  verbose?: boolean;         // Show progress messages (default: false)
}
```

## 🚨 Important Notes

1. **Composite Primary Key**: The table uses `(id, metricVersion)` as the primary key, so the same CVE ID can have multiple entries with different metric versions.

2. **File Location**: The database file is created in your project root by default. You can specify a different path.

3. **Backup**: Always creates a backup before updating existing data.

4. **Memory Efficient**: Processes large datasets in batches to avoid memory issues.

5. **SQLite Compatibility**: Uses standard SQLite features, so the database file works with any SQLite tool or library.

## 🆚 SQLite vs SQL File Generation

| Feature | SQLite (.db) | SQL File (.sql) |
|---------|-------------|-----------------|
| **Usage** | Direct database access | Import into database |
| **File Size** | Compact binary format | Large text file |
| **Query Speed** | Fast with indexes | Requires import first |
| **Portability** | Works with any SQLite tool | Database-specific |
| **Local Development** | ✅ Perfect for local apps | ❌ Requires database setup |
| **Production** | ✅ Great for small-medium apps | ✅ Better for large deployments |

For your local small app, SQLite is the perfect choice! 🎯
