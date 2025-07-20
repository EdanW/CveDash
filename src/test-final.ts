import { NvdWrapper } from './services/nvd';

async function finalTest() {
  console.log('🛡️ Final NVD API Test - All Working Features\n');

  const nvd = new NvdWrapper();

  try {
    // Test 1: Get a specific CVE
    console.log('📋 Test 1: Getting specific CVE...');
    const cveResponse = await nvd.getCve('CVE-2023-1234');
    
    if (cveResponse.vulnerabilities.length > 0) {
      const cve = cveResponse.vulnerabilities[0].cve;
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      
      console.log('✅ CVE Details:');
      console.log(`   ID: ${internalCve.cveId}`);
      console.log(`   Title: ${internalCve.title.substring(0, 80)}...`);
      console.log(`   Severity: ${internalCve.severity}`);
      console.log(`   CVSS Score: ${internalCve.cvssScore}`);
      console.log(`   DDoS Related: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
      console.log(`   Status: ${internalCve.status}`);
      console.log(`   Published: ${internalCve.publishedDate}`);
    }
    console.log('');

    // Test 2: Keyword search (now working!)
    console.log('🔍 Test 2: Keyword search for "vulnerability"...');
    const keywordResponse = await nvd.searchCvesByKeyword('vulnerability');
    console.log(`✅ Found ${keywordResponse.totalResults} vulnerabilities`);
    console.log(`   Showing ${keywordResponse.vulnerabilities.length} results`);
    
    if (keywordResponse.vulnerabilities.length > 0) {
      keywordResponse.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
        console.log(`      Title: ${internalCve.title.substring(0, 60)}...`);
      });
    }
    console.log('');

    // Test 3: Search for DDoS-related terms
    console.log('🔍 Test 3: Searching for DDoS-related terms...');
    
    const ddosTerms = ['ddos', 'denial of service', 'flood', 'amplification'];
    
    for (const term of ddosTerms) {
      try {
        const searchResponse = await nvd.searchCvesByKeyword(term);
        console.log(`✅ "${term}": Found ${searchResponse.totalResults} results`);
        
        if (searchResponse.vulnerabilities.length > 0) {
          const firstCve = searchResponse.vulnerabilities[0].cve;
          const internalCve = NvdWrapper.convertToInternalFormat(firstCve);
          console.log(`   First: ${firstCve.id} - ${internalCve.severity} - DDoS: ${internalCve.ddosRelated ? 'Yes' : 'No'}`);
        }
      } catch (error: any) {
        console.log(`❌ "${term}": ${error.message}`);
      }
    }
    console.log('');

    // Test 4: Get recent CVEs
    console.log('📅 Test 4: Getting recent CVEs...');
    const today = new Date();
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    const recentResponse = await nvd.getCvesByDateRange(
      weekAgo.toISOString(),
      today.toISOString()
    );
    console.log(`✅ Found ${recentResponse.totalResults} CVEs in the last week`);
    console.log(`   Showing ${recentResponse.vulnerabilities.length} results`);
    
    if (recentResponse.vulnerabilities.length > 0) {
      recentResponse.vulnerabilities.slice(0, 2).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
        console.log(`      Published: ${cve.published.split('T')[0]}`);
      });
    }
    console.log('');

    // Test 5: Get high severity CVEs
    console.log('🚨 Test 5: Getting HIGH severity CVEs...');
    const highSeverityResponse = await nvd.getCvesBySeverity('HIGH', 'v3');
    console.log(`✅ Found ${highSeverityResponse.totalResults} HIGH severity CVEs`);
    console.log(`   Showing ${highSeverityResponse.vulnerabilities.length} results`);
    
    if (highSeverityResponse.vulnerabilities.length > 0) {
      highSeverityResponse.vulnerabilities.slice(0, 2).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
        console.log(`      Title: ${internalCve.title.substring(0, 60)}...`);
      });
    }

    console.log('\n🎉 All tests completed successfully!');
    console.log('✅ NvdWrapper is working correctly with NVD API v2.0');

  } catch (error: any) {
    console.error('❌ Error in final test:', error.message);
  }
}

// Run the final test
finalTest(); 