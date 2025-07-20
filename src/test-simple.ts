import { NvdWrapper } from './services/nvd';

async function simpleTest() {
  console.log('🛡️ Simple NVD API Test...\n');

  const nvd = new NvdWrapper();

  try {
    // Test 1: Get a specific CVE (this worked)
    console.log('📋 Test 1: Getting CVE-2023-1234...');
    const cveResponse = await nvd.getCve('CVE-2023-1234');
    
    if (cveResponse.vulnerabilities.length > 0) {
      const cve = cveResponse.vulnerabilities[0].cve;
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      
      console.log('✅ Success! CVE Details:');
      console.log(`   ID: ${internalCve.cveId}`);
      console.log(`   Title: ${internalCve.title.substring(0, 80)}...`);
      console.log(`   Severity: ${internalCve.severity}`);
      console.log(`   CVSS Score: ${internalCve.cvssScore}`);
      console.log(`   DDoS Related: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
      console.log(`   Status: ${internalCve.status}`);
      console.log(`   Published: ${internalCve.publishedDate}`);
      console.log(`   Modified: ${internalCve.modifiedDate}`);
    }
    console.log('');

    // Test 2: Try a different search approach
    console.log('🔍 Test 2: Trying alternative search...');
    try {
      // Try searching with different parameters
      const searchResponse = await nvd.searchCvesByKeyword('vulnerability', false);
      console.log(`✅ Search successful! Found ${searchResponse.totalResults} results`);
      console.log(`   Showing ${searchResponse.vulnerabilities.length} vulnerabilities`);
      
      if (searchResponse.vulnerabilities.length > 0) {
        const firstCve = searchResponse.vulnerabilities[0].cve;
        const internalFirst = NvdWrapper.convertToInternalFormat(firstCve);
        console.log(`   First result: ${firstCve.id} - ${internalFirst.severity}`);
      }
    } catch (searchError: any) {
      console.log(`❌ Search failed: ${searchError.message}`);
    }
    console.log('');

    // Test 3: Get recent CVEs (this should work)
    console.log('📅 Test 3: Getting recent CVEs...');
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    
    const recentResponse = await nvd.getCvesByDateRange(
      yesterday.toISOString().split('T')[0],
      today.toISOString().split('T')[0]
    );
    console.log(`✅ Recent CVEs: Found ${recentResponse.totalResults} CVEs from yesterday`);
    console.log(`   Showing ${recentResponse.vulnerabilities.length} results`);
    
    if (recentResponse.vulnerabilities.length > 0) {
      recentResponse.vulnerabilities.slice(0, 2).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
      });
    }

  } catch (error) {
    console.error('❌ Error in simple test:', error);
  }
}

// Run the test
simpleTest(); 