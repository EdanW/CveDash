#!/usr/bin/env ts-node

/**
 * Test script to query DDoS-related CVEs with CVSS v4.0
 * Usage: npx ts-node src/scripts/testDdosV4Query.ts
 */

import * as path from 'path';
import { CveSqliteManager } from './saveToSqlite';

async function queryDdosV4Cves() {
  console.log('🔍 Querying DDoS-related CVEs with CVSS v4.0...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    // Query DDoS-related CVEs with CVSS v4.0
    const ddosV4Cves = await manager.queryEntries({
      isDdosRelated: true,
      metricVersion: '4.0',
      limit: 100,
      statusFilter: 'accepted' // Only get accepted/analyzed CVEs
    });

    console.log(`📊 Found ${ddosV4Cves.length} DDoS-related CVEs with CVSS v4.0\n`);

    if (ddosV4Cves.length === 0) {
      console.log('❌ No DDoS-related CVEs found with CVSS v4.0');
      console.log('💡 This could mean:');
      console.log('   - CVSS v4.0 is very new and few CVEs use it yet');
      console.log('   - DDoS detection may not be finding v4.0 CVEs');
      console.log('   - Database may not contain recent CVE data');
      
      // Let's check what we do have
      console.log('\n🔍 Let\'s check what data is available...\n');
      
      // Check total DDoS CVEs
      const totalDdos = await manager.queryEntries({
        isDdosRelated: true,
        limit: 10
      });
      console.log(`📈 Total DDoS-related CVEs (any version): ${totalDdos.length > 0 ? 'Found some' : 'None found'}`);
      
      if (totalDdos.length > 0) {
        console.log('   Sample DDoS CVEs:');
        totalDdos.slice(0, 3).forEach((cve, index) => {
          console.log(`   ${index + 1}. ${cve.id} (CVSS v${cve.metricVersion}) - Score: ${cve.baseScore}`);
        });
      }
      
      // Check total v4.0 CVEs
      const totalV4 = await manager.queryEntries({
        metricVersion: '4.0',
        limit: 10
      });
      console.log(`\n📈 Total CVEs with CVSS v4.0 (any type): ${totalV4.length > 0 ? 'Found some' : 'None found'}`);
      
      if (totalV4.length > 0) {
        console.log('   Sample CVSS v4.0 CVEs:');
        totalV4.slice(0, 3).forEach((cve, index) => {
          console.log(`   ${index + 1}. ${cve.id} - Score: ${cve.baseScore} (DDoS: ${cve.isDdosRelated ? 'Yes' : 'No'})`);
        });
      }
      
      return;
    }

    // Display results
    console.log('📋 DDoS-related CVEs with CVSS v4.0:');
    console.log('=' .repeat(80));
    
    ddosV4Cves.forEach((cve, index) => {
      console.log(`\n${index + 1}. ${cve.id}`);
      console.log(`   📊 CVSS v4.0 Score: ${cve.baseScore} (${cve.baseSeverity})`);
      console.log(`   📅 Published: ${cve.published}`);
      console.log(`   🎯 Attack Vector: ${cve.attackVector}`);
      console.log(`   📝 Description: ${cve.description.substring(0, 120)}...`);
    });

    // Show statistics
    console.log('\n' + '=' .repeat(80));
    console.log('📊 Statistics:');
    
    const scores = ddosV4Cves.map(cve => cve.baseScore).filter(score => score !== null);
    if (scores.length > 0) {
      const avgScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;
      const minScore = Math.min(...scores);
      const maxScore = Math.max(...scores);
      
      console.log(`   Average CVSS Score: ${avgScore.toFixed(2)}`);
      console.log(`   Score Range: ${minScore} - ${maxScore}`);
    }
    
    const severityCount: Record<string, number> = {};
    ddosV4Cves.forEach(cve => {
      const severity = cve.baseSeverity || 'UNKNOWN';
      severityCount[severity] = (severityCount[severity] || 0) + 1;
    });
    
    console.log('   Severity Distribution:');
    Object.entries(severityCount).forEach(([severity, count]) => {
      console.log(`     ${severity}: ${count}`);
    });

    // Show years distribution
    const yearCount: Record<string, number> = {};
    ddosV4Cves.forEach(cve => {
      if (cve.published) {
        const year = cve.published.substring(0, 4);
        yearCount[year] = (yearCount[year] || 0) + 1;
      }
    });
    
    if (Object.keys(yearCount).length > 0) {
      console.log('   Year Distribution:');
      Object.entries(yearCount)
        .sort(([a], [b]) => b.localeCompare(a)) // Sort by year descending
        .forEach(([year, count]) => {
          console.log(`     ${year}: ${count}`);
        });
    }

  } catch (error) {
    console.error('❌ Query failed:', error);
    process.exit(1);
  } finally {
    await manager.close();
  }
}

// Run the query
if (require.main === module) {
  queryDdosV4Cves().catch(console.error);
}
