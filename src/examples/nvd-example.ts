import { NvdWrapper } from '../services/nvd';

// Simple example of how to use the NvdWrapper
async function simpleExample() {
  console.log('🛡️ Simple NVD API Example\n');

  const nvd = new NvdWrapper();

  try {
    // Get a specific CVE
    console.log('📋 Getting CVE-2023-1234...');
    const response = await nvd.getCve('CVE-2023-1234');
    
    if (response.vulnerabilities.length > 0) {
      const cve = response.vulnerabilities[0].cve;
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      
      console.log('✅ CVE Details:');
      console.log(`   ID: ${internalCve.cveId}`);
      console.log(`   Title: ${internalCve.title}`);
      console.log(`   Severity: ${internalCve.severity}`);
      console.log(`   CVSS Score: ${internalCve.cvssScore}`);
      console.log(`   DDoS Related: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
      console.log(`   Status: ${internalCve.status}`);
    } else {
      console.log('❌ CVE not found');
    }

  } catch (error) {
    console.error('❌ Error:', error);
  }
}

// Quick test function
async function quickTest() {
  console.log('⚡ Quick NVD Test\n');
  
  const nvd = new NvdWrapper();
  
  try {
    // Search for DDoS CVEs
    const ddosCves = await nvd.searchCvesByKeyword('ddos', false);
    console.log(`Found ${ddosCves.totalResults} DDoS-related CVEs`);
    
    // Show first 3 results
    ddosCves.vulnerabilities.slice(0, 3).forEach((vuln, i) => {
      const cve = vuln.cve;
      const internal = NvdWrapper.convertToInternalFormat(cve);
      console.log(`${i + 1}. ${cve.id} - ${internal.severity} (CVSS: ${internal.cvssScore})`);
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
  }
}

// Export functions for use in other files
export { simpleExample, quickTest };

// Run if this file is executed directly
if (require.main === module) {
  simpleExample();
} 