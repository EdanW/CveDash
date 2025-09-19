#!/usr/bin/env ts-node

/**
 * Test script to verify yearly trends work with status filtering
 */

import { getYearlyCveTrends, getYearlyDdosTrends } from './queries/getSeveritiesDistribution';
import { MetricVersion } from './scripts/extractTableEntriesFromJson';

async function testYearlyTrendsWithStatus() {
  console.log('🧪 Testing Yearly Trends with Status Filtering...\n');

  const statusFilters: Array<'accepted' | 'open-accepted' | 'all'> = ['accepted', 'open-accepted', 'all'];

  try {
    console.log('📈 Testing All CVE Yearly Trends:\n');

    for (const statusFilter of statusFilters) {
      console.log(`--- Status Filter: "${statusFilter}" ---`);
      
      const startTime = Date.now();
      const yearlyData = await getYearlyCveTrends(MetricVersion.V31, undefined, statusFilter);
      const endTime = Date.now();
      
      const totalCves = Object.values(yearlyData).reduce((sum, count) => sum + count, 0);
      const years = Object.keys(yearlyData).filter(year => yearlyData[year] > 0);
      
      console.log(`   Query time: ${endTime - startTime}ms`);
      console.log(`   Total CVEs: ${totalCves.toLocaleString()}`);
      console.log(`   Years with data: ${years.length} (${years[0]} to ${years[years.length - 1]})`);
      console.log(`   Sample years:`, Object.fromEntries(
        Object.entries(yearlyData)
          .filter(([_, count]) => count > 0)
          .slice(-5) // Last 5 years with data
      ));
      console.log('');
    }

    console.log('🛡️ Testing DDoS CVE Yearly Trends:\n');

    for (const statusFilter of statusFilters) {
      console.log(`--- Status Filter: "${statusFilter}" ---`);
      
      const startTime = Date.now();
      const yearlyDdosData = await getYearlyDdosTrends(MetricVersion.V31, undefined, statusFilter);
      const endTime = Date.now();
      
      const totalDdosCves = Object.values(yearlyDdosData).reduce((sum, count) => sum + count, 0);
      const years = Object.keys(yearlyDdosData).filter(year => yearlyDdosData[year] > 0);
      
      console.log(`   Query time: ${endTime - startTime}ms`);
      console.log(`   Total DDoS CVEs: ${totalDdosCves.toLocaleString()}`);
      console.log(`   Years with data: ${years.length} (${years[0]} to ${years[years.length - 1]})`);
      console.log(`   Sample years:`, Object.fromEntries(
        Object.entries(yearlyDdosData)
          .filter(([_, count]) => count > 0)
          .slice(-5) // Last 5 years with data
      ));
      console.log('');
    }

    console.log('✅ Yearly trends status filtering tests completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testYearlyTrendsWithStatus().catch(console.error);
}

export { testYearlyTrendsWithStatus };
