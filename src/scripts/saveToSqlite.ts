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
        isDdosRelated INTEGER DEFAULT 0,
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
        attackVector, attackComplexity, exploitabilityScore, impactScore, cweIds, isDdosRelated,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `
      : `
      INSERT OR IGNORE INTO ${this.tableName} (
        id, sourceIdentifier, published, lastModified, vulnStatus, description,
        metricVersion, source, baseScore, vectorString, baseSeverity,
        attackVector, attackComplexity, exploitabilityScore, impactScore, cweIds, isDdosRelated,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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
            entry.cweIds && entry.cweIds.length > 0 ? JSON.stringify(entry.cweIds) : null,
            entry.isDdosRelated ? 1 : 0
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
    isDdosRelated?: boolean;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<TableEntry[]> {
    const { limit = 100, offset = 0, severity, minScore, maxScore, id, metricVersion, isDdosRelated, publishedAfter, publishedBefore, statusFilter } = options;

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

    if (isDdosRelated !== undefined) {
      whereClause += whereClause ? ' AND isDdosRelated = ?' : ' WHERE isDdosRelated = ?';
      params.push(isDdosRelated ? 1 : 0);
    }

    if (publishedAfter) {
      whereClause += whereClause ? ' AND published >= ?' : ' WHERE published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += whereClause ? ' AND published <= ?' : ' WHERE published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += whereClause ? ' AND (vulnStatus = ? OR vulnStatus = ?)' : ' WHERE (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += whereClause ? ' AND vulnStatus != ?' : ' WHERE vulnStatus != ?';
      params.push('Rejected');
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
            cweIds: row.cweIds ? JSON.parse(row.cweIds) : [],
            isDdosRelated: !!row.isDdosRelated
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
   * Get yearly CVE trends with unique CVE counting at SQL level
   * Returns count of unique CVEs per year regardless of metric version
   */
  async getYearlyCveTrends(options: {
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<Record<string, number>> {
    await this.openDatabase();

    const { statusFilter } = options;
    
    let whereClause = `WHERE published IS NOT NULL
        AND published != ''
        AND CAST(strftime('%Y', published) AS INTEGER) BETWEEN 1998 AND 2025`;
    const params: any[] = [];

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    const query = `
      SELECT 
        CAST(strftime('%Y', published) AS TEXT) as year,
        COUNT(DISTINCT SUBSTR(id, 1, CASE WHEN id LIKE 'CVE-%' THEN LENGTH(id) ELSE LENGTH(id) END)) as count
      FROM ${this.tableName}
      ${whereClause}
      GROUP BY strftime('%Y', published)
      ORDER BY year
    `;

    return new Promise((resolve, reject) => {
      this.db!.all(query, params, (err, rows: any[]) => {
        if (err) {
          reject(err);
        } else {
          const yearlyData: Record<string, number> = {};
          
          // Initialize all years 1998-2025 with 0
          for (let year = 1998; year <= 2025; year++) {
            yearlyData[year.toString()] = 0;
          }
          
          // Fill in actual data
          rows.forEach(row => {
            if (row.year) {
              yearlyData[row.year] = row.count || 0;
            }
          });
          
          resolve(yearlyData);
        }
      });
    });
  }

  /**
   * Get yearly DDoS CVE trends with unique CVE counting at SQL level
   * Returns count of unique DDoS-related CVEs per year regardless of metric version
   */
  async getYearlyDdosTrends(options: {
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<Record<string, number>> {
    await this.openDatabase();

    const { statusFilter } = options;
    
    let whereClause = `WHERE published IS NOT NULL
        AND published != ''
        AND isDdosRelated = 1
        AND CAST(strftime('%Y', published) AS INTEGER) BETWEEN 1998 AND 2025`;
    const params: any[] = [];

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    const query = `
      SELECT 
        CAST(strftime('%Y', published) AS TEXT) as year,
        COUNT(DISTINCT SUBSTR(id, 1, CASE WHEN id LIKE 'CVE-%' THEN LENGTH(id) ELSE LENGTH(id) END)) as count
      FROM ${this.tableName}
      ${whereClause}
      GROUP BY strftime('%Y', published)
      ORDER BY year
    `;

    return new Promise((resolve, reject) => {
      this.db!.all(query, params, (err, rows: any[]) => {
        if (err) {
          reject(err);
        } else {
          const yearlyData: Record<string, number> = {};
          
          // Initialize all years 1998-2025 with 0
          for (let year = 1998; year <= 2025; year++) {
            yearlyData[year.toString()] = 0;
          }
          
          // Fill in actual data
          rows.forEach(row => {
            if (row.year) {
              yearlyData[row.year] = row.count || 0;
            }
          });
          
          resolve(yearlyData);
        }
      });
    });
  }

  /**
   * Close the database connection (call this when done)
   */
  async close(): Promise<void> {
    await this.closeDatabase();
  }

  /**
   * Get severity distribution with SQL-level grouping for better performance
   * Returns count of entries grouped by severity for a specific metric version
   */
  async getSeverityDistribution(options: {
    metricVersion?: string;
    isDdosRelated?: boolean;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<Record<string, number>> {
    await this.openDatabase();

    const { metricVersion, isDdosRelated, publishedAfter, publishedBefore, statusFilter } = options;

    let whereClause = '';
    const params: any[] = [];

    if (metricVersion) {
      whereClause += ' WHERE metricVersion = ?';
      params.push(metricVersion);
    }

    if (isDdosRelated !== undefined) {
      whereClause += whereClause ? ' AND isDdosRelated = ?' : ' WHERE isDdosRelated = ?';
      params.push(isDdosRelated ? 1 : 0);
    }

    if (publishedAfter) {
      whereClause += whereClause ? ' AND published >= ?' : ' WHERE published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += whereClause ? ' AND published <= ?' : ' WHERE published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      // Only show Analyzed and Modified status
      whereClause += whereClause ? ' AND (vulnStatus = ? OR vulnStatus = ?)' : ' WHERE (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      // Show Received, Awaiting Analysis, Undergoing Analysis, Analyzed, and Modified (exclude Rejected)
      whereClause += whereClause ? ' AND vulnStatus != ?' : ' WHERE vulnStatus != ?';
      params.push('Rejected');
    }
    // 'all' filter doesn't add any WHERE clause - shows everything including rejected

    const query = `
      SELECT 
        COALESCE(baseSeverity, 'UNKNOWN') as severity,
        COUNT(*) as count
      FROM ${this.tableName}
      ${whereClause}
      GROUP BY COALESCE(baseSeverity, 'UNKNOWN')
      ORDER BY 
        CASE COALESCE(baseSeverity, 'UNKNOWN')
          WHEN 'CRITICAL' THEN 1
          WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3
          WHEN 'LOW' THEN 4
          WHEN 'UNKNOWN' THEN 5
          ELSE 6
        END
    `;

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      this.db.all(query, params, (err: Error | null, rows: any[]) => {
        if (err) {
          reject(err);
          return;
        }

        const distribution: Record<string, number> = {};
        rows.forEach(row => {
          distribution[row.severity] = row.count;
        });

        resolve(distribution);
      });
    });
  }

  /**
   * Get average base score with SQL-level calculation for better performance
   * Returns the average base score for entries matching the given criteria
   */
  async getAverageBaseScore(options: {
    metricVersion?: string;
    isDdosRelated?: boolean;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<number> {
    await this.openDatabase();

    const { metricVersion, isDdosRelated, publishedAfter, publishedBefore, statusFilter } = options;

    let whereClause = 'WHERE baseScore IS NOT NULL AND baseScore >= 0';
    const params: any[] = [];

    if (metricVersion) {
      whereClause += ' AND metricVersion = ?';
      params.push(metricVersion);
    }

    if (isDdosRelated !== undefined) {
      whereClause += ' AND isDdosRelated = ?';
      params.push(isDdosRelated ? 1 : 0);
    }

    if (publishedAfter) {
      whereClause += ' AND published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += ' AND published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    const query = `
      SELECT AVG(baseScore) as averageScore
      FROM ${this.tableName}
      ${whereClause}
    `;

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      this.db.get(query, params, (err: Error | null, row: any) => {
        if (err) {
          reject(err);
          return;
        }

        const averageScore = row?.averageScore || 0;
        resolve(Math.round(averageScore * 100) / 100); // Round to 2 decimal places
      });
    });
  }

  /**
   * Get CWE statistics for DDoS-related entries
   * Returns count of unique CWE IDs from DDoS-related CVEs
   */
  /**
   * Get CVSS score distribution in ranges for histogram visualization
   * Returns count of entries grouped by score ranges
   */
  async getCvssScoreDistribution(options: {
    metricVersion?: string;
    isDdosRelated?: boolean;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<Array<{
    range: string;
    count: number;
    minScore: number;
    maxScore: number;
  }>> {
    await this.openDatabase();

    const { metricVersion, isDdosRelated, publishedAfter, publishedBefore, statusFilter } = options;

    let whereClause = 'WHERE baseScore IS NOT NULL AND baseScore >= 0';
    const params: any[] = [];

    if (metricVersion) {
      whereClause += ' AND metricVersion = ?';
      params.push(metricVersion);
    }

    if (isDdosRelated !== undefined) {
      whereClause += ' AND isDdosRelated = ?';
      params.push(isDdosRelated ? 1 : 0);
    }

    if (publishedAfter) {
      whereClause += ' AND published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += ' AND published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    // Create score ranges using CASE statements
    const query = `
      SELECT 
        CASE 
          WHEN baseScore >= 0 AND baseScore < 1 THEN '0.0-0.9'
          WHEN baseScore >= 1 AND baseScore < 2 THEN '1.0-1.9'
          WHEN baseScore >= 2 AND baseScore < 3 THEN '2.0-2.9'
          WHEN baseScore >= 3 AND baseScore < 4 THEN '3.0-3.9'
          WHEN baseScore >= 4 AND baseScore < 5 THEN '4.0-4.9'
          WHEN baseScore >= 5 AND baseScore < 6 THEN '5.0-5.9'
          WHEN baseScore >= 6 AND baseScore < 7 THEN '6.0-6.9'
          WHEN baseScore >= 7 AND baseScore < 8 THEN '7.0-7.9'
          WHEN baseScore >= 8 AND baseScore < 9 THEN '8.0-8.9'
          WHEN baseScore >= 9 AND baseScore <= 10 THEN '9.0-10.0'
          ELSE 'Unknown'
        END as scoreRange,
        COUNT(*) as count,
        CASE 
          WHEN baseScore >= 0 AND baseScore < 1 THEN 0
          WHEN baseScore >= 1 AND baseScore < 2 THEN 1
          WHEN baseScore >= 2 AND baseScore < 3 THEN 2
          WHEN baseScore >= 3 AND baseScore < 4 THEN 3
          WHEN baseScore >= 4 AND baseScore < 5 THEN 4
          WHEN baseScore >= 5 AND baseScore < 6 THEN 5
          WHEN baseScore >= 6 AND baseScore < 7 THEN 6
          WHEN baseScore >= 7 AND baseScore < 8 THEN 7
          WHEN baseScore >= 8 AND baseScore < 9 THEN 8
          WHEN baseScore >= 9 AND baseScore <= 10 THEN 9
          ELSE 0
        END as minScore,
        CASE 
          WHEN baseScore >= 0 AND baseScore < 1 THEN 0.9
          WHEN baseScore >= 1 AND baseScore < 2 THEN 1.9
          WHEN baseScore >= 2 AND baseScore < 3 THEN 2.9
          WHEN baseScore >= 3 AND baseScore < 4 THEN 3.9
          WHEN baseScore >= 4 AND baseScore < 5 THEN 4.9
          WHEN baseScore >= 5 AND baseScore < 6 THEN 5.9
          WHEN baseScore >= 6 AND baseScore < 7 THEN 6.9
          WHEN baseScore >= 7 AND baseScore < 8 THEN 7.9
          WHEN baseScore >= 8 AND baseScore < 9 THEN 8.9
          WHEN baseScore >= 9 AND baseScore <= 10 THEN 10.0
          ELSE 0
        END as maxScore
      FROM ${this.tableName}
      ${whereClause}
      GROUP BY scoreRange, minScore, maxScore
      ORDER BY minScore
    `;

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      this.db.all(query, params, (err: Error | null, rows: any[]) => {
        if (err) {
          reject(err);
          return;
        }

        const result = rows.map(row => ({
          range: row.scoreRange,
          count: row.count,
          minScore: row.minScore,
          maxScore: row.maxScore
        }));

        resolve(result);
      });
    });
  }

  /**
   * Get CVSS score statistics (min, max, median, etc.)
   */
  async getCvssScoreStats(options: {
    metricVersion?: string;
    isDdosRelated?: boolean;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
  } = {}): Promise<{
    min: number;
    max: number;
    median: number;
  }> {
    await this.openDatabase();

    const { metricVersion, isDdosRelated, publishedAfter, publishedBefore, statusFilter } = options;

    let whereClause = 'WHERE baseScore IS NOT NULL AND baseScore >= 0';
    const params: any[] = [];

    if (metricVersion) {
      whereClause += ' AND metricVersion = ?';
      params.push(metricVersion);
    }

    if (isDdosRelated !== undefined) {
      whereClause += ' AND isDdosRelated = ?';
      params.push(isDdosRelated ? 1 : 0);
    }

    if (publishedAfter) {
      whereClause += ' AND published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += ' AND published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    const query = `
      SELECT 
        MIN(baseScore) as minScore,
        MAX(baseScore) as maxScore,
        COUNT(*) as totalCount
      FROM ${this.tableName}
      ${whereClause}
    `;

    // For median, we need a separate query
    const medianQuery = `
      SELECT baseScore
      FROM ${this.tableName}
      ${whereClause}
      ORDER BY baseScore
      LIMIT 1 OFFSET (
        SELECT (COUNT(*) - 1) / 2
        FROM ${this.tableName}
        ${whereClause}
      )
    `;

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      // Get min/max first
      this.db.get(query, params, (err: Error | null, row: any) => {
        if (err) {
          reject(err);
          return;
        }

        const minScore = row?.minScore || 0;
        const maxScore = row?.maxScore || 0;
        const totalCount = row?.totalCount || 0;

        if (totalCount === 0) {
          resolve({ min: 0, max: 0, median: 0 });
          return;
        }

        // Get median
        if (!this.db) {
          reject(new Error('Database not initialized'));
          return;
        }
        
        this.db.get(medianQuery, params, (medianErr: Error | null, medianRow: any) => {
          if (medianErr) {
            reject(medianErr);
            return;
          }

          const median = medianRow?.baseScore || 0;
          resolve({
            min: Math.round(minScore * 100) / 100,
            max: Math.round(maxScore * 100) / 100,
            median: Math.round(median * 100) / 100
          });
        });
      });
    });
  }

  async getCweStatistics(options: {
    metricVersion?: string;
    publishedAfter?: string;
    publishedBefore?: string;
    statusFilter?: 'accepted' | 'open-accepted' | 'all';
    limit?: number;
  } = {}): Promise<Array<{ cweId: string; count: number }>> {
    await this.openDatabase();

    const { metricVersion, publishedAfter, publishedBefore, statusFilter, limit = 5 } = options;

    let whereClause = ' WHERE isDdosRelated = 1 AND cweIds IS NOT NULL AND cweIds != \'\' AND cweIds != \'[]\'';
    const params: any[] = [];

    if (metricVersion) {
      whereClause += ' AND metricVersion = ?';
      params.push(metricVersion);
    }

    if (publishedAfter) {
      whereClause += ' AND published >= ?';
      params.push(publishedAfter);
    }

    if (publishedBefore) {
      whereClause += ' AND published <= ?';
      params.push(publishedBefore);
    }

    // Add status filtering
    if (statusFilter === 'accepted') {
      whereClause += ' AND (vulnStatus = ? OR vulnStatus = ? OR vulnStatus = ?)';
      params.push('Analyzed', 'Modified', 'Deferred');
    } else if (statusFilter === 'open-accepted') {
      whereClause += ' AND vulnStatus != ?';
      params.push('Rejected');
    }

    const query = `
      SELECT cweIds
      FROM ${this.tableName}
      ${whereClause}
    `;

    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not initialized'));
        return;
      }

      this.db.all(query, params, (err: Error | null, rows: any[]) => {
        if (err) {
          reject(err);
          return;
        }

        // Count CWE IDs across all entries
        const cweCounts: { [cweId: string]: number } = {};
        
        rows.forEach(row => {
          try {
            const cweIds: string[] = JSON.parse(row.cweIds);
            cweIds.forEach(cweId => {
              if (cweId && typeof cweId === 'string' && 
                  cweId !== 'NVD-CWE-Other' && 
                  cweId !== 'NVD-CWE-noinfo' && 
                  cweId !== 'Unknown CWE') {
                cweCounts[cweId] = (cweCounts[cweId] || 0) + 1;
              }
            });
          } catch (parseError) {
            // Skip invalid JSON entries
            console.warn('Failed to parse CWE IDs:', row.cweIds);
          }
        });

        // Convert to array and sort by count (descending)
        const result = Object.entries(cweCounts)
          .map(([cweId, count]) => ({ cweId, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, limit);

        resolve(result);
      });
    });
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
        cweIds: ['CWE-79', 'CWE-89'],
        isDdosRelated: false
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
