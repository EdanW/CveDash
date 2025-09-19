#!/usr/bin/env ts-node

/**
 * Test script to verify SQL-optimized severity distribution calculation
 * This compares the old JavaScript-based grouping with the new SQL-based grouping
 */

import { CveSqliteManager } from './scripts/saveToSqlite';
import { getSeveritiesDistribution, getMetricVersionStats } from './queries/getSeveritiesDistribution';
import { MetricVersion } from './scripts/extractTableEntriesFromJson';
import * as path from 'path';

async function testSqlOptimization() {
  console.log('🧪 Testing SQL-optimized severity distribution calculation...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    // Test the new SQL-based severity distribution method
    console.log('📊 Testing SQL-based severity distribution:');
    const startTime = Date.now();
    
    const sqlDistribution = await manager.getSeverityDistribution({
      metricVersion: MetricVersion.V31,
      isDdosRelated: true
    });
    
    const sqlTime = Date.now() - startTime;
    console.log(`   SQL method took: ${sqlTime}ms`);
    console.log('   Distribution:', sqlDistribution);

    // Test the updated getSeveritiesDistribution function
    console.log('\n📊 Testing updated getSeveritiesDistribution function:');
    const startTime2 = Date.now();
    
    const functionDistribution = await getSeveritiesDistribution(MetricVersion.V31);
    
    const functionTime = Date.now() - startTime2;
    console.log(`   Function method took: ${functionTime}ms`);
    console.log('   Distribution:', functionDistribution);

    // Test the updated getMetricVersionStats function
    console.log('\n📊 Testing updated getMetricVersionStats function:');
    const startTime3 = Date.now();
    
    const stats = await getMetricVersionStats(MetricVersion.V31, undefined, true);
    
    const statsTime = Date.now() - startTime3;
    console.log(`   Stats method took: ${statsTime}ms`);
    console.log('   Stats:');
    console.log(`     Total entries: ${stats.totalEntries}`);
    console.log(`     Average score: ${stats.averageScore}`);
    console.log('     Severity distribution:', stats.severityDistribution);

    // Test SQL-based average score calculation
    console.log('\n📊 Testing SQL-based average score calculation:');
    const startTime4 = Date.now();
    
    const avgScore = await manager.getAverageBaseScore({
      metricVersion: MetricVersion.V31,
      isDdosRelated: true
    });
    
    const avgTime = Date.now() - startTime4;
    console.log(`   Average score method took: ${avgTime}ms`);
    console.log(`   Average score: ${avgScore}`);

    console.log('\n✅ All tests completed successfully!');
    console.log(`\n⚡ Performance summary:`);
    console.log(`   SQL distribution: ${sqlTime}ms`);
    console.log(`   Function distribution: ${functionTime}ms`);
    console.log(`   Stats calculation: ${statsTime}ms`);
    console.log(`   Average score: ${avgTime}ms`);

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await manager.close();
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testSqlOptimization().catch(console.error);
}

export { testSqlOptimization };
