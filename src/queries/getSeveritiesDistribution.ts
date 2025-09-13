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
  dbPath?: string
): Promise<Record<string, number>> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Query entries with the specific metric version directly from the database
    const entries = await manager.queryEntries({ 
      metricVersion: metricVersion,
      limit: 1000000 // Use a very large limit to get all entries
    });
    
    // Count severities
    const distribution: Record<string, number> = {};
    
    for (const entry of entries) {
      const severity = entry.baseSeverity || 'UNKNOWN';
      distribution[severity] = (distribution[severity] || 0) + 1;
    }

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
  dbPath?: string
): Promise<{
  metricVersion: MetricVersion;
  totalEntries: number;
  severityDistribution: Record<string, number>;
  averageScore: number;
}> {
  const databasePath = dbPath || path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(databasePath);

  try {
    // Query entries with the specific metric version directly from the database
    const entries = await manager.queryEntries({ 
      metricVersion: metricVersion,
      limit: 1000000 // Use a very large limit to get all entries
    });

    if (entries.length === 0) {
      return {
        metricVersion,
        totalEntries: 0,
        severityDistribution: {},
        averageScore: 0
      };
    }

    // Calculate statistics
    const severityDistribution: Record<string, number> = {};
    const scores: number[] = [];

    for (const entry of entries) {
      const severity = entry.baseSeverity || 'UNKNOWN';
      severityDistribution[severity] = (severityDistribution[severity] || 0) + 1;
      
      if (typeof entry.baseScore === 'number' && entry.baseScore >= 0) {
        scores.push(entry.baseScore);
      }
    }

    const averageScore = scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;

    return {
      metricVersion,
      totalEntries: entries.length,
      severityDistribution,
      averageScore: Math.round(averageScore * 100) / 100 // Round to 2 decimal places
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

// Run example if this file is executed directly
if (require.main === module) {
  exampleUsage().catch(console.error);
}
