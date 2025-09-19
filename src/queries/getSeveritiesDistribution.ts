import { CveSqliteManager } from '../scripts/saveToSqlite';
import { MetricVersion } from '../scripts/extractTableEntriesFromJson';
import * as path from 'path';

/**
 * Gets the distribution of severities for a specific metric version
 * @param metricVersion - The CVSS metric version to filter by
 * @param dbPath - Optional path to the database file (defaults to cve_database.db)
 * @returns Promise<Record<string, number>> - Object with severity as key and count as value
 */
export async function getSeveritiesDistribution(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all'
): Promise<Record<string, number>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Use SQL-level grouping for better performance
    const distribution = await manager.getSeverityDistribution({
      metricVersion: metricVersion,
      isDdosRelated: true, // Get DDoS-related CVEs only
      statusFilter: statusFilter || 'accepted' // Default to accepted only
    });

    return distribution;

  } catch (error) {
    console.error('Error getting severities distribution:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

/**
 * Gets detailed statistics for a specific metric version including severity distribution
 * @param metricVersion - The CVSS metric version to filter by
 * @param dbPath - Optional path to the database file
 * @returns Promise with detailed statistics
 */
export async function getMetricVersionStats(
  metricVersion: MetricVersion,
  dbPath?: string,
  isDdosRelated?: boolean,
  statusFilter?: 'accepted' | 'open-accepted' | 'all'
): Promise<{
  metricVersion: MetricVersion;
  totalEntries: number;
  severityDistribution: Record<string, number>;
  averageScore: number;
}> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Use SQL-level grouping for severity distribution
    const severityDistribution = await manager.getSeverityDistribution({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    // Calculate total entries from the distribution
    const totalEntries = Object.values(severityDistribution).reduce((sum, count) => sum + count, 0);

    if (totalEntries === 0) {
      return {
        metricVersion,
        totalEntries: 0,
        severityDistribution: {},
        averageScore: 0
      };
    }

    // Use SQL-level calculation for average score as well
    const averageScore = await manager.getAverageBaseScore({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    return {
      metricVersion,
      totalEntries,
      severityDistribution,
      averageScore // Already rounded in the SQL method
    };

  } catch (error) {
    console.error('Error getting metric version stats:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

// Example usage function
export async function exampleUsage() {
  console.log('📊 Severity Distribution Examples:\n');

  try {
    // Get distribution for CVSS 3.1
    console.log('CVSS 3.1 Severity Distribution:');
    const cvss31Distribution = await getSeveritiesDistribution(MetricVersion.V31);
    console.log(cvss31Distribution);

    // Get detailed stats for CVSS 4.0
    console.log('\nCVSS 4.0 Detailed Statistics:');
    const cvss40Stats = await getMetricVersionStats(MetricVersion.V40);
    console.log(cvss40Stats);

    // Get distribution for CVSS 2.0
    console.log('\nCVSS 2.0 Severity Distribution:');
    const cvss20Distribution = await getSeveritiesDistribution(MetricVersion.V20);
    console.log(cvss20Distribution);

  } catch (error) {
    console.error('Error in example usage:', error);
  }
}

/**
 * Gets yearly CVE distribution counting unique CVEs regardless of metric version
 * Uses optimized SQL query to handle uniqueness at database level
 * @param metricVersion - The CVSS metric version (kept for API compatibility, but not used for filtering)
 * @param dbPath - Optional path to the database file (defaults to cve_database.db)
 * @returns Promise<Record<string, number>> - Object with year as key and unique CVE count as value
 */
export async function getYearlyCveTrends(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all'
): Promise<Record<string, number>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Use optimized SQL query that handles uniqueness at database level
    const yearlyDistribution = await manager.getYearlyCveTrends({
      statusFilter: statusFilter || 'accepted'
    });
    return yearlyDistribution;

  } catch (error) {
    console.error('Error getting yearly CVE trends:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

/**
 * Gets yearly DDoS-related CVE distribution counting unique CVEs regardless of metric version
 * Uses optimized SQL query to handle uniqueness at database level
 * @param metricVersion - The CVSS metric version (kept for API compatibility, but not used for filtering)
 * @param dbPath - Optional path to the database file (defaults to cve_database.db)
 * @returns Promise<Record<string, number>> - Object with year as key and unique DDoS CVE count as value
 */
export async function getYearlyDdosTrends(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all'
): Promise<Record<string, number>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Use optimized SQL query that handles uniqueness at database level
    const yearlyDistribution = await manager.getYearlyDdosTrends({
      statusFilter: statusFilter || 'accepted'
    });
    return yearlyDistribution;

  } catch (error) {
    console.error('Error getting yearly DDoS trends:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  exampleUsage().catch(console.error);
}
