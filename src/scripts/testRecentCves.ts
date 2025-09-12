import * as fs from 'fs';
import * as path from 'path';
import { extractTableEntriesFromJson } from './extractTableEntriesFromJson';

const RECENT_CVES_PATH = path.join(process.cwd(), 'cveJsons', 'nvdcve-2.0-recent.json');

/**
 * Test script to verify that the downloaded recent CVEs can be processed
 */
async function testRecentCves(): Promise<void> {
  try {
    console.log('Testing recent CVEs processing...');
    
    // Check if the file exists
    if (!fs.existsSync(RECENT_CVES_PATH)) {
      throw new Error(`Recent CVEs file not found at: ${RECENT_CVES_PATH}`);
    }

    // Read and parse the JSON
    const jsonContent = fs.readFileSync(RECENT_CVES_PATH, 'utf8');
    const cveData = JSON.parse(jsonContent);

    console.log(`Found ${cveData.vulnerabilities?.length || 0} vulnerabilities`);
    console.log(`Total results: ${cveData.totalResults || 'Unknown'}`);
    console.log(`Format: ${cveData.format || 'Unknown'}`);
    console.log(`Timestamp: ${cveData.timestamp || 'Unknown'}`);

    // Test processing the first few CVEs
    const vulnerabilities = cveData.vulnerabilities || [];
    const testCount = Math.min(3, vulnerabilities.length);
    
    console.log(`\nTesting processing of first ${testCount} CVEs:`);
    
    for (let i = 0; i < testCount; i++) {
      const vulnerability = vulnerabilities[i];
      const cve = vulnerability.cve;
      
      console.log(`\n--- CVE ${i + 1}: ${cve.id} ---`);
      console.log(`Published: ${cve.published}`);
      console.log(`Status: ${cve.vulnStatus}`);
      
      try {
        // Test the extraction function
        const tableEntries = extractTableEntriesFromJson(cve);
        console.log(`✅ Successfully processed CVE ${cve.id}`);
        console.log(`   Found ${tableEntries.length} metric entries`);
        
        if (tableEntries.length > 0) {
          const entry = tableEntries[0]; // Show first entry
          console.log(`   Description: ${entry.description.substring(0, 100)}...`);
          console.log(`   Base Score: ${entry.baseScore}`);
          console.log(`   Severity: ${entry.baseSeverity}`);
          console.log(`   Metric Version: ${entry.metricVersion}`);
        }
      } catch (error) {
        console.log(`❌ Failed to process CVE ${cve.id}:`, error);
      }
    }

    console.log('\n✅ Recent CVEs test completed successfully!');

  } catch (error) {
    console.error('❌ Error testing recent CVEs:', error);
    throw error;
  }
}

// Run if this script is executed directly
if (require.main === module) {
  testRecentCves().catch(console.error);
}

export { testRecentCves };
