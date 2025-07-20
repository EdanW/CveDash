import { NvdWrapper } from './services/nvd';

async function testKeywordSearch() {
  console.log('🔍 Testing NVD API Keyword Search...\n');

  const nvd = new NvdWrapper();

  try {
    // Test different keyword search approaches
    console.log('📋 Test 1: Basic keyword search...');
    
    // Try searching for "vulnerability" first (should work)
    const basicSearch = await nvd.searchCvesByKeyword('vulnerability', false);
    console.log(`✅ Basic search: Found ${basicSearch.totalResults} results`);
    console.log(`   Showing ${basicSearch.vulnerabilities.length} vulnerabilities`);
    
    if (basicSearch.vulnerabilities.length > 0) {
      const firstCve = basicSearch.vulnerabilities[0].cve;
      const internalFirst = NvdWrapper.convertToInternalFormat(firstCve);
      console.log(`   First result: ${firstCve.id} - ${internalFirst.severity}`);
    }
    console.log('');

    // Test 2: Try searching for "ddos" with different approach
    console.log('📋 Test 2: DDoS keyword search...');
    try {
      const ddosSearch = await nvd.searchCvesByKeyword('ddos', false);
      console.log(`✅ DDoS search: Found ${ddosSearch.totalResults} results`);
      console.log(`   Showing ${ddosSearch.vulnerabilities.length} vulnerabilities`);
      
      if (ddosSearch.vulnerabilities.length > 0) {
        ddosSearch.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
          const cve = vuln.cve;
          const internalCve = NvdWrapper.convertToInternalFormat(cve);
          console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
          console.log(`      DDoS Related: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
        });
      }
    } catch (ddosError: any) {
      console.log(`❌ DDoS search failed: ${ddosError.message}`);
    }
    console.log('');

    // Test 3: Try searching for "denial of service"
    console.log('📋 Test 3: "Denial of service" keyword search...');
    try {
      const dosSearch = await nvd.searchCvesByKeyword('denial of service', false);
      console.log(`✅ DoS search: Found ${dosSearch.totalResults} results`);
      console.log(`   Showing ${dosSearch.vulnerabilities.length} vulnerabilities`);
      
      if (dosSearch.vulnerabilities.length > 0) {
        dosSearch.vulnerabilities.slice(0, 2).forEach((vuln, index) => {
          const cve = vuln.cve;
          const internalCve = NvdWrapper.convertToInternalFormat(cve);
          console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
          console.log(`      DDoS Related: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
        });
      }
    } catch (dosError: any) {
      console.log(`❌ DoS search failed: ${dosError.message}`);
    }

  } catch (error: any) {
    console.error('❌ Error in keyword test:', error.message);
  }
}

// Run the test
testKeywordSearch(); 