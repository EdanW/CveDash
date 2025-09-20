import { CveSqliteManager } from '../scripts/saveToSqlite';
import { MetricVersion } from '../scripts/extractTableEntriesFromJson';
import * as path from 'path';

/**
 * Gets the distribution of CVSS scores in ranges for histogram visualization
 * @param metricVersion - The CVSS metric version to filter by
 * @param dbPath - Optional path to the database file (defaults to cve_database.db)
 * @param statusFilter - Filter by vulnerability status
 * @param isDdosRelated - Optional filter for DDoS-related CVEs only
 * @returns Promise<Array<{range: string, count: number, minScore: number, maxScore: number}>> - Array of score ranges with counts
 */
export async function getCvssScoreDistribution(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all',
  isDdosRelated?: boolean
): Promise<Array<{
  range: string;
  count: number;
  minScore: number;
  maxScore: number;
}>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Use SQL-level grouping for better performance
    const scoreDistribution = await manager.getCvssScoreDistribution({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    return scoreDistribution;

  } catch (error) {
    console.error('Error getting CVSS score distribution:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

/**
 * Gets detailed CVSS score statistics
 * @param metricVersion - The CVSS metric version to filter by
 * @param dbPath - Optional path to the database file
 * @param statusFilter - Filter by vulnerability status
 * @param isDdosRelated - Optional filter for DDoS-related CVEs only
 * @returns Promise with detailed CVSS statistics
 */
export async function getCvssScoreStats(
  metricVersion: MetricVersion,
  dbPath?: string,
  statusFilter?: 'accepted' | 'open-accepted' | 'all',
  isDdosRelated?: boolean
): Promise<{
  metricVersion: MetricVersion;
  totalEntries: number;
  averageScore: number;
  medianScore: number;
  minScore: number;
  maxScore: number;
  scoreDistribution: Array<{
    range: string;
    count: number;
    minScore: number;
    maxScore: number;
  }>;
}> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Get score distribution
    const scoreDistribution = await manager.getCvssScoreDistribution({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    // Calculate total entries from the distribution
    const totalEntries = scoreDistribution.reduce((sum, range) => sum + range.count, 0);

    if (totalEntries === 0) {
      return {
        metricVersion,
        totalEntries: 0,
        averageScore: 0,
        medianScore: 0,
        minScore: 0,
        maxScore: 0,
        scoreDistribution: []
      };
    }

    // Get additional statistics
    const averageScore = await manager.getAverageBaseScore({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    const scoreStats = await manager.getCvssScoreStats({
      metricVersion: metricVersion,
      isDdosRelated: isDdosRelated,
      statusFilter: statusFilter || 'accepted'
    });

    return {
      metricVersion,
      totalEntries,
      averageScore,
      medianScore: scoreStats.median,
      minScore: scoreStats.min,
      maxScore: scoreStats.max,
      scoreDistribution
    };

  } catch (error) {
    console.error('Error getting CVSS score stats:', error);
    throw error;
  } finally {
    await manager.close();
  }
}

// Example usage function
export async function exampleUsage() {
  console.log('📊 CVSS Score Distribution Examples:\n');

  try {
    // Get distribution for CVSS 3.1
    console.log('CVSS 3.1 Score Distribution:');
    const cvss31Distribution = await getCvssScoreDistribution(MetricVersion.V31);
    console.log(cvss31Distribution);

    // Get detailed stats for CVSS 4.0
    console.log('\nCVSS 4.0 Detailed Score Statistics:');
    const cvss40Stats = await getCvssScoreStats(MetricVersion.V40);
    console.log(cvss40Stats);

    // Get distribution for DDoS-related CVEs only
    console.log('\nDDoS-related CVSS 3.1 Score Distribution:');
    const ddosCvss31Distribution = await getCvssScoreDistribution(MetricVersion.V31, undefined, 'accepted', true);
    console.log(ddosCvss31Distribution);

  } catch (error) {
    console.error('Error in example usage:', error);
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  exampleUsage().catch(console.error);
}
