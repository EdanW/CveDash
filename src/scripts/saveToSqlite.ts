import * as sqlite3 from 'sqlite3';
import * as fs from 'fs';
import * as path from 'path';
import { TableEntry, MetricVersion } from './extractTableEntriesFromJson';

/**
 * SQLite Database Manager for CVE Table Entries
 * Works directly with .db files - no need to import SQL files
 */
export class CveSqliteManager {
  private dbPath: string;
  private tableName: string = 'cve_entries';
  private db: sqlite3.Database | null = null;

  constructor(dbPath: string, tableName?: string) {
    this.dbPath = path.resolve(dbPath);
    if (tableName) {
      this.tableName = tableName;
    }
  }

  /**
   * Initialize the SQLite database connection
   */
  private async openDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(new Error(`Failed to open database: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Close the database connection
   */
  private async closeDatabase(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            reject(new Error(`Failed to close database: ${err.message}`));
          } else {
            this.db = null;
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Check if the database file exists
   */
  private databaseExists(): boolean {
    return fs.existsSync(this.dbPath);
  }

  /**
   * Check if the table exists in the database
   */
  private async tableExists(): Promise<boolean> {
    if (!this.db) {
      throw new Error('Database not connected');
    }

    return new Promise((resolve, reject) => {
      const query = `
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=?
      `;
      
      this.db!.get(query, [this.tableName], (err, row) => {
        if (err) {
          reject(new Error(`Failed to check table existence: ${err.message}`));
        } else {
          resolve(!!row);
        }
      });
    });
  }

  /**
   * Create the CVE entries table
   */
  private async createTable(): Promise<void> {
    if (!this.db) {
      throw new Error('Database not connected');
    }

    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
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
      )
    `;

    return new Promise((resolve, reject) => {
      this.db!.run(createTableSQL, (err) => {
        if (err) {
          reject(new Error(`Failed to create table: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Create indexes for better performance
   */
  private async createIndexes(): Promise<void> {
    if (!this.db) {
      throw new Error('Database not connected');
    }

    const indexes = [
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_published ON ${this.tableName}(published)`,
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_baseScore ON ${this.tableName}(baseScore)`,
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_baseSeverity ON ${this.tableName}(baseSeverity)`,
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_metricVersion ON ${this.tableName}(metricVersion)`,
      `CREATE INDEX IF NOT EXISTS idx_${this.tableName}_id ON ${this.tableName}(id)`
    ];

    for (const indexSQL of indexes) {
      await new Promise<void>((resolve, reject) => {
        this.db!.run(indexSQL, (err) => {
          if (err) {
            reject(new Error(`Failed to create index: ${err.message}`));
          } else {
            resolve();
          }
        });
      });
    }
  }

  /**
   * Main function to save TableEntry array to SQLite database
   */
  async saveToSqlite(
    entries: TableEntry[],
    options: {
      createBackup?: boolean;
      batchSize?: number;
      verbose?: boolean;
      saveMode?: 'upsert' | 'insertOnly';
    } = {}
  ): Promise<void> {
    const { createBackup = true, batchSize = 1000, verbose = false, saveMode = 'upsert' } = options;

    if (verbose) {
      console.log(`[SQLite] Starting save operation for ${entries.length} entries to ${this.dbPath}`);
    }

    try {
      // Create backup if database exists
      if (createBackup && this.databaseExists()) {
        await this.createBackup();
      }

      // Open database connection
      await this.openDatabase();

      // Check if table exists
      const tableExists = await this.tableExists();

      if (!tableExists) {
        if (verbose) {
          console.log('[SQLite] Creating table and indexes');
        }
        await this.createTable();
        await this.createIndexes();
      } else {
        if (verbose) {
          console.log('[SQLite] Table exists, will update/insert entries');
        }
      }

      // Process entries in batches
      await this.processEntriesInBatches(entries, batchSize, verbose, saveMode);

      if (verbose) {
        console.log(`[SQLite] Successfully saved ${entries.length} entries to ${this.dbPath}`);
      }

    } finally {
      // Always close the database connection
      await this.closeDatabase();
    }
  }

  /**
   * Create a backup of the existing database
   */
  private async createBackup(): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `${this.dbPath}.backup.${timestamp}`;
    
    try {
      fs.copyFileSync(this.dbPath, backupPath);
      console.log(`[SQLite] Backup created: ${backupPath}`);
    } catch (error) {
      console.warn('[SQLite] Failed to create backup:', error);
    }
  }

  /**
   * Process entries in batches
   */
  private async processEntriesInBatches(
    entries: TableEntry[],
    batchSize: number,
    verbose: boolean,
    saveMode: 'upsert' | 'insertOnly'
  ): Promise<void> {
    const totalBatches = Math.ceil(entries.length / batchSize);
    
    for (let i = 0; i < totalBatches; i++) {
      const start = i * batchSize;
      const end = Math.min(start + batchSize, entries.length);
      const batch = entries.slice(start, end);
      
      if (verbose) {
        console.log(`[SQLite] Processing batch ${i + 1}/${totalBatches} (${batch.length} entries)`);
      }
      
      await this.processBatch(batch, saveMode);
    }
  }

  /**
   * Process a single batch of entries using INSERT OR REPLACE
   */
  private async processBatch(entries: TableEntry[], saveMode: 'upsert' | 'insertOnly'): Promise<void> {
    if (!this.db || entries.length === 0) return;

    const insertSQL = saveMode === 'upsert'
      ? `
      INSERT OR REPLACE INTO ${this.tableName} (
        id, sourceIdentifier, published, lastModified, vulnStatus, description,
        metricVersion, source, baseScore, vectorString, baseSeverity,
        attackVector, attackComplexity, exploitabilityScore, impactScore, cweIds,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `
      : `
      INSERT OR IGNORE INTO ${this.tableName} (
        id, sourceIdentifier, published, lastModified, vulnStatus, description,
        metricVersion, source, baseScore, vectorString, baseSeverity,
        attackVector, attackComplexity, exploitabilityScore, impactScore, cweIds,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `;

    return new Promise((resolve, reject) => {
      this.db!.serialize(() => {
        this.db!.run('BEGIN TRANSACTION');
        
        const stmt = this.db!.prepare(insertSQL);
        
        entries.forEach((entry, index) => {
          stmt.run([
            entry.id,
            entry.sourceIdentifier,
            entry.published,
            entry.lastModified,
            entry.vulnStatus,
            entry.description,
            entry.metricVersion,
            entry.source,
            entry.baseScore !== -1 ? entry.baseScore : null,
            entry.vectorString,
            entry.baseSeverity,
            entry.attackVector,
            entry.attackComplexity,
            entry.exploitabilityScore !== -1 ? entry.exploitabilityScore : null,
            entry.impactScore !== -1 ? entry.impactScore : null,
            entry.cweIds && entry.cweIds.length > 0 ? JSON.stringify(entry.cweIds) : null
          ], (err) => {
            if (err) {
              reject(new Error(`Failed to insert entry ${index}: ${err.message}`));
            }
          });
        });
        
        stmt.finalize((err) => {
          if (err) {
            reject(new Error(`Failed to finalize statement: ${err.message}`));
          } else {
            this.db!.run('COMMIT', (err) => {
              if (err) {
                reject(new Error(`Failed to commit transaction: ${err.message}`));
              } else {
                resolve();
              }
            });
          }
        });
      });
    });
  }

  /**
   * Query entries from the database
   */
  async queryEntries(options: {
    limit?: number;
    offset?: number;
    severity?: string;
    minScore?: number;
    maxScore?: number;
    id?: string;
    metricVersion?: string;
  } = {}): Promise<TableEntry[]> {
    const { limit = 100, offset = 0, severity, minScore, maxScore, id, metricVersion } = options;

    await this.openDatabase();

    let whereClause = '';
    const params: any[] = [];

    if (id) {
      whereClause += ' WHERE id = ?';
      params.push(id);
    }

    if (severity) {
      whereClause += whereClause ? ' AND baseSeverity = ?' : ' WHERE baseSeverity = ?';
      params.push(severity);
    }

    if (minScore !== undefined) {
      whereClause += whereClause ? ' AND baseScore >= ?' : ' WHERE baseScore >= ?';
      params.push(minScore);
    }

    if (maxScore !== undefined) {
      whereClause += whereClause ? ' AND baseScore <= ?' : ' WHERE baseScore <= ?';
      params.push(maxScore);
    }

    if (metricVersion) {
      whereClause += whereClause ? ' AND metricVersion = ?' : ' WHERE metricVersion = ?';
      params.push(metricVersion);
    }

    const query = `
      SELECT * FROM ${this.tableName}
      ${whereClause}
      ORDER BY published DESC
      LIMIT ? OFFSET ?
    `;

    params.push(limit, offset);

    return new Promise((resolve, reject) => {
      this.db!.all(query, params, (err, rows: any[]) => {
        if (err) {
          reject(new Error(`Query failed: ${err.message}`));
        } else {
          const entries: TableEntry[] = rows.map(row => ({
            id: row.id,
            sourceIdentifier: row.sourceIdentifier,
            published: row.published,
            lastModified: row.lastModified,
            vulnStatus: row.vulnStatus,
            description: row.description,
            metricVersion: row.metricVersion as MetricVersion,
            source: row.source,
            baseScore: row.baseScore || -1,
            vectorString: row.vectorString,
            baseSeverity: row.baseSeverity,
            attackVector: row.attackVector,
            attackComplexity: row.attackComplexity,
            exploitabilityScore: row.exploitabilityScore || -1,
            impactScore: row.impactScore || -1,
            cweIds: row.cweIds ? JSON.parse(row.cweIds) : []
          }));
          resolve(entries);
        }
      });
    });
  }

  /**
   * Get database statistics
   */
  async getStats(): Promise<{
    totalEntries: number;
    entriesBySeverity: { [key: string]: number };
    entriesByMetricVersion: { [key: string]: number };
    dateRange: { earliest: string; latest: string };
  }> {
    await this.openDatabase();

    const stats = await Promise.all([
      // Total entries
      new Promise<number>((resolve, reject) => {
        this.db!.get(`SELECT COUNT(*) as count FROM ${this.tableName}`, (err, row: any) => {
          if (err) reject(err);
          else resolve(row.count);
        });
      }),
      // Entries by severity
      new Promise<{ [key: string]: number }>((resolve, reject) => {
        this.db!.all(
          `SELECT baseSeverity, COUNT(*) as count FROM ${this.tableName} GROUP BY baseSeverity`,
          (err, rows: any[]) => {
            if (err) reject(err);
            else {
              const result: { [key: string]: number } = {};
              rows.forEach(row => result[row.baseSeverity] = row.count);
              resolve(result);
            }
          }
        );
      }),
      // Entries by metric version
      new Promise<{ [key: string]: number }>((resolve, reject) => {
        this.db!.all(
          `SELECT metricVersion, COUNT(*) as count FROM ${this.tableName} GROUP BY metricVersion`,
          (err, rows: any[]) => {
            if (err) reject(err);
            else {
              const result: { [key: string]: number } = {};
              rows.forEach(row => result[row.metricVersion] = row.count);
              resolve(result);
            }
          }
        );
      }),
      // Date range
      new Promise<{ earliest: string; latest: string }>((resolve, reject) => {
        this.db!.get(
          `SELECT MIN(published) as earliest, MAX(published) as latest FROM ${this.tableName}`,
          (err, row: any) => {
            if (err) reject(err);
            else resolve({ earliest: row.earliest || '', latest: row.latest || '' });
          }
        );
      })
    ]);

    return {
      totalEntries: stats[0],
      entriesBySeverity: stats[1],
      entriesByMetricVersion: stats[2],
      dateRange: stats[3]
    };
  }

  /**
   * Close the database connection (call this when done)
   */
  async close(): Promise<void> {
    await this.closeDatabase();
  }
}

/**
 * Convenience function to save TableEntry array to SQLite database
 */
export async function saveTableEntriesToSqlite(
  entries: TableEntry[],
  dbPath: string,
  options: {
    tableName?: string;
    createBackup?: boolean;
    batchSize?: number;
    verbose?: boolean;
    saveMode?: 'upsert' | 'insertOnly';
  } = {}
): Promise<void> {
  const manager = new CveSqliteManager(dbPath, options.tableName);
  await manager.saveToSqlite(entries, options);
  await manager.close();
}

/**
 * Example usage function
 */
export async function exampleSqliteUsage(): Promise<void> {
  const exampleEntries: TableEntry[] = [
    {
      id: 'CVE-2023-1234',
      sourceIdentifier: 'nvd@nist.gov',
      published: '2023-01-01T00:00:00.000Z',
      lastModified: '2023-01-02T00:00:00.000Z',
      vulnStatus: 'Analyzed',
      description: 'Example vulnerability description',
      metricVersion: MetricVersion.V31,
      source: 'nvd@nist.gov',
      baseScore: 7.5,
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      baseSeverity: 'HIGH',
      attackVector: 'NETWORK',
      attackComplexity: 'LOW',
      exploitabilityScore: 3.9,
      impactScore: 3.6,
      cweIds: ['CWE-79', 'CWE-89']
    }
  ];

  try {
    await saveTableEntriesToSqlite(
      exampleEntries,
      './cve_database.db',
      {
        tableName: 'cve_entries',
        createBackup: true,
        batchSize: 1000,
        verbose: true
      }
    );
    console.log('✅ Successfully saved entries to SQLite database');
  } catch (error) {
    console.error('❌ Error saving to SQLite:', error);
  }
}

export { saveTableEntriesToSqlite as default };
