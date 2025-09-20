import { CveSqliteManager } from '../scripts/saveToSqlite';
import { MetricVersion } from '../scripts/extractTableEntriesFromJson';
import * as path from 'path';

/**
 * Gets CWE statistics for DDoS-related entries
 * @param metricVersion - The CVSS metric version to filter by
 * @param dbPath - Optional path to the database file (defaults to cve_database.db)
 * @param statusFilter - Status filter for entries
 * @param limit - Maximum number of CWE entries to return (defaults to 5)
 * @returns Promise<Array<{ cweId: string; count: number }>> - Array of CWE statistics sorted by count
 */
export async function getCweStatistics(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all',
  limit?: number
): Promise<Array<{ cweId: string; count: number }>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    const cweStats = await manager.getCweStatistics({
      metricVersion: metricVersion,
      statusFilter: statusFilter || 'accepted',
      limit: limit || 5
    });

    return cweStats;

  } catch (error) {
    console.error('Error getting CWE statistics:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

/**
 * Gets CWE statistics with additional filtering options
 * @param options - Configuration options for the query
 * @returns Promise<Array<{ cweId: string; count: number }>> - Array of CWE statistics
 */
export async function getCweStatisticsWithFilters(options: {
  metricVersion?: MetricVersion;
  dbPath?: string;
  statusFilter?: 'accepted' | 'open-accepted' | 'all';
  publishedAfter?: string;
  publishedBefore?: string;
  limit?: number;
}): Promise<Array<{ cweId: string; count: number }>> {
  const databasePath = options.dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    const cweStats = await manager.getCweStatistics({
      metricVersion: options.metricVersion,
      statusFilter: options.statusFilter || 'accepted',
      publishedAfter: options.publishedAfter,
      publishedBefore: options.publishedBefore,
      limit: options.limit || 5
    });

    return cweStats;

  } catch (error) {
    console.error('Error getting CWE statistics with filters:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

// Example usage function
export async function exampleUsage() {
  console.log('🔧 CWE Statistics Examples:\n');

  try {
    // Get top 5 CWEs for CVSS 3.1
    console.log('Top 5 CWEs for CVSS 3.1:');
    const cvss31Cwes = await getCweStatistics(MetricVersion.V31, undefined, 'accepted', 5);
    console.log(cvss31Cwes);

    // Get top 10 CWEs for CVSS 4.0
    console.log('\nTop 10 CWEs for CVSS 4.0:');
    const cvss40Cwes = await getCweStatistics(MetricVersion.V40, undefined, 'accepted', 10);
    console.log(cvss40Cwes);

    // Get CWE statistics with year filter
    console.log('\nTop 5 CWEs for 2023 (CVSS 3.1):');
    const yearlyCwes = await getCweStatisticsWithFilters({
      metricVersion: MetricVersion.V31,
      statusFilter: 'accepted',
      publishedAfter: '2023-01-01',
      publishedBefore: '2023-12-31',
      limit: 5
    });
    console.log(yearlyCwes);

  } catch (error) {
    console.error('Error in example usage:', error);
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  exampleUsage().catch(console.error);
}
