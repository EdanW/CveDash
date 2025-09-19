#!/usr/bin/env ts-node

/**
 * Test script to verify status filtering functionality
 * Tests the complete flow from database to frontend
 */

import { getSeveritiesDistribution, getMetricVersionStats } from './queries/getSeveritiesDistribution';
import { CveSqliteManager } from './scripts/saveToSqlite';
import { MetricVersion } from './scripts/extractTableEntriesFromJson';
import * as path from 'path';

async function testStatusFiltering() {
  console.log('🧪 Testing Status Filtering Functionality...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    console.log('📊 Testing Severity Distribution with Different Status Filters:\n');

    // Test all three status filter options
    const statusFilters: Array<'accepted' | 'open-accepted' | 'all'> = ['accepted', 'open-accepted', 'all'];

    for (const statusFilter of statusFilters) {
      console.log(`--- Status Filter: "${statusFilter}" ---`);
      
      const startTime = Date.now();
      const distribution = await getSeveritiesDistribution(MetricVersion.V31, undefined, statusFilter);
      const endTime = Date.now();
      
      const totalEntries = Object.values(distribution).reduce((sum, count) => sum + count, 0);
      
      console.log(`   Query time: ${endTime - startTime}ms`);
      console.log(`   Total entries: ${totalEntries.toLocaleString()}`);
      console.log('   Distribution:', distribution);
      console.log('');
    }

    console.log('📈 Testing Metric Version Stats with Status Filtering:\n');

    // Test metric version stats with different filters
    for (const statusFilter of statusFilters) {
      console.log(`--- Status Filter: "${statusFilter}" ---`);
      
      const startTime = Date.now();
      const stats = await getMetricVersionStats(MetricVersion.V31, undefined, true, statusFilter);
      const endTime = Date.now();
      
      console.log(`   Query time: ${endTime - startTime}ms`);
      console.log(`   Total entries: ${stats.totalEntries.toLocaleString()}`);
      console.log(`   Average score: ${stats.averageScore}`);
      console.log('   Severity distribution:', stats.severityDistribution);
      console.log('');
    }

    console.log('🔍 Testing Direct Database Queries with Status Filtering:\n');

    // Test direct database queries
    for (const statusFilter of statusFilters) {
      console.log(`--- Status Filter: "${statusFilter}" ---`);
      
      const startTime = Date.now();
      
      // Test severity distribution
      const severityDist = await manager.getSeverityDistribution({
        metricVersion: MetricVersion.V31,
        isDdosRelated: true,
        statusFilter: statusFilter
      });
      
      // Test average score
      const avgScore = await manager.getAverageBaseScore({
        metricVersion: MetricVersion.V31,
        isDdosRelated: true,
        statusFilter: statusFilter
      });
      
      // Test sample entries
      const sampleEntries = await manager.queryEntries({
        metricVersion: MetricVersion.V31,
        isDdosRelated: true,
        statusFilter: statusFilter,
        limit: 5
      });
      
      const endTime = Date.now();
      
      const totalEntries = Object.values(severityDist).reduce((sum, count) => sum + count, 0);
      
      console.log(`   Query time: ${endTime - startTime}ms`);
      console.log(`   Total entries: ${totalEntries.toLocaleString()}`);
      console.log(`   Average score: ${avgScore}`);
      console.log(`   Sample entries: ${sampleEntries.length}`);
      console.log('   Status values in sample:', [...new Set(sampleEntries.map(e => e.vulnStatus))]);
      console.log('');
    }

    console.log('✅ Status filtering tests completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await manager.close();
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testStatusFiltering().catch(console.error);
}

export { testStatusFiltering };
