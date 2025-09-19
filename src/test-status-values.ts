#!/usr/bin/env ts-node

/**
 * Test script to check different vulnerability status values in the database
 * This will show what status values exist and their meanings
 */

import { CveSqliteManager } from './scripts/saveToSqlite';
import * as path from 'path';

// Helper function to get status distribution
async function getStatusDistribution(manager: CveSqliteManager): Promise<any[]> {
  // Use a simple query to get some sample data and analyze status values
  const sampleEntries = await manager.queryEntries({limit: 200000});
  
  // Count status values manually
  const statusCounts: Record<string, number> = {};
  sampleEntries.forEach(entry => {
    const status = entry.vulnStatus || 'NULL';
    statusCounts[status] = (statusCounts[status] || 0) + 1;
  });

  // Convert to array format
  const total = sampleEntries.length;
  return Object.entries(statusCounts)
    .map(([vulnStatus, count]) => ({
      vulnStatus,
      count,
      percentage: Math.round((count * 100.0) / total * 100) / 100
    }))
    .sort((a, b) => b.count - a.count);
}

// Helper function to get examples for a status
async function getStatusExamples(manager: CveSqliteManager, status: string): Promise<any[]> {
  const entries = await manager.queryEntries({ limit: 1000 });
  return entries
    .filter(entry => entry.vulnStatus === status)
    .slice(0, 3)
    .map(entry => ({
      id: entry.id,
      published: entry.published,
      lastModified: entry.lastModified,
      description: entry.description
    }));
}

async function checkStatusValues() {
  console.log('🔍 Checking vulnerability status values in database...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    // Get distinct status values and their counts using a custom SQL method
    console.log('📊 Vulnerability Status Distribution:');
    
    // Add a public method to get status distribution
    const statusResults = await getStatusDistribution(manager);

    statusResults.forEach((row, index) => {
      console.log(`   ${index + 1}. "${row.vulnStatus}" - ${row.count.toLocaleString()} entries (${row.percentage}%)`);
    });

    // Get some examples for each status
    console.log('\n📋 Examples for each status:');
    for (const statusRow of statusResults.slice(0, 5)) { // Limit to top 5 status types
      console.log(`\n--- Status: "${statusRow.vulnStatus}" ---`);
      
      const examples = await getStatusExamples(manager, statusRow.vulnStatus);

      examples.forEach((example, i) => {
        console.log(`   ${i + 1}. ${example.id}`);
        console.log(`      Published: ${example.published}`);
        console.log(`      Modified: ${example.lastModified}`);
        console.log(`      Description: ${example.description.substring(0, 100)}...`);
      });
    }

    // Check how status mapping works in the application
    console.log('\n🔄 Status Mapping in Application:');
    console.log('   From the codebase analysis:');
    console.log('   - "Analyzed" → mapped to "ACTIVE" in frontend');
    console.log('   - Other values → mapped to "INVESTIGATING" in frontend');
    
    // Show the mapping logic
    statusResults.forEach(row => {
      const mappedStatus = row.vulnStatus === 'Analyzed' ? 'ACTIVE' : 'INVESTIGATING';
      console.log(`   - "${row.vulnStatus}" → "${mappedStatus}" (${row.count.toLocaleString()} entries)`);
    });

    // Get total database stats
    console.log('\n📈 Database Overview:');
    const stats = await manager.getStats();
    
    console.log(`   Total CVE entries: ${stats.totalEntries.toLocaleString()}`);
    console.log(`   Distinct status values: ${statusResults.length}`);
    console.log(`   Date range: ${stats.dateRange.earliest} to ${stats.dateRange.latest}`);

  } catch (error) {
    console.error('❌ Error checking status values:', error);
  } finally {
    await manager.close();
  }
}

// Documentation about NVD vulnerability status values
function showStatusDocumentation() {
  console.log('\n📚 NVD Vulnerability Status Documentation:');
  console.log('');
  console.log('According to NVD documentation, vulnStatus can have these values:');
  console.log('');
  console.log('🔹 "Received" - CVE has been received by NVD but not yet processed');
  console.log('🔹 "Awaiting Analysis" - CVE is in queue for analysis');
  console.log('🔹 "Undergoing Analysis" - CVE is currently being analyzed');
  console.log('🔹 "Analyzed" - CVE has been fully analyzed and scored');
  console.log('🔹 "Modified" - CVE analysis has been updated/modified');
  console.log('🔹 "Rejected" - CVE was rejected (not a valid vulnerability)');
  console.log('');
  console.log('In your application:');
  console.log('✅ "Analyzed" status CVEs are shown as "ACTIVE" (ready for use)');
  console.log('⏳ All other statuses are shown as "INVESTIGATING" (pending analysis)');
  console.log('');
}

// Run the test if this file is executed directly
if (require.main === module) {
  showStatusDocumentation();
  checkStatusValues().catch(console.error);
}

export { checkStatusValues, showStatusDocumentation };
