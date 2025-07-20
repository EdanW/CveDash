import { NvdWrapper } from './services/nvd';

async function testNvdWrapper() {
  console.log('🛡️ Testing NVD API Wrapper...\n');

  // Initialize the wrapper (you can optionally provide an API key for higher rate limits)
  const nvd = new NvdWrapper();

  try {
    // Test 1: Get a specific CVE
    console.log('📋 Test 1: Getting specific CVE (CVE-2023-1234)...');
    const cveResponse = await nvd.getCve('CVE-2023-1234');
    console.log(`Found ${cveResponse.vulnerabilities.length} vulnerabilities`);
    
    if (cveResponse.vulnerabilities.length > 0) {
      const cve = cveResponse.vulnerabilities[0].cve;
      console.log(`CVE ID: ${cve.id}`);
      console.log(`Title: ${cve.descriptions.find(d => d.lang === 'en')?.value.substring(0, 100)}...`);
      console.log(`Published: ${cve.published}`);
      console.log(`Status: ${cve.vulnStatus}`);
      
      // Convert to our internal format
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      console.log(`Internal format - Severity: ${internalCve.severity}, CVSS: ${internalCve.cvssScore}, DDoS Related: ${internalCve.ddosRelated}`);
    }
    console.log('');

    // Test 2: Search for DDoS-related CVEs
    console.log('🔍 Test 2: Searching for DDoS-related CVEs...');
    const ddosResponse = await nvd.searchCvesByKeyword('ddos', false);
    console.log(`Found ${ddosResponse.totalResults} DDoS-related CVEs`);
    console.log(`Showing ${ddosResponse.vulnerabilities.length} results`);
    
    ddosResponse.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
      const cve = vuln.cve;
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      console.log(`${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
      console.log(`   DDoS Related: ${internalCve.ddosRelated}`);
    });
    console.log('');

    // Test 3: Get high severity CVEs
    console.log('🚨 Test 3: Getting HIGH severity CVEs...');
    const highSeverityResponse = await nvd.getCvesBySeverity('HIGH', 'v3');
    console.log(`Found ${highSeverityResponse.totalResults} HIGH severity CVEs`);
    console.log(`Showing ${highSeverityResponse.vulnerabilities.length} results`);
    
    highSeverityResponse.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
      const cve = vuln.cve;
      console.log(`${index + 1}. ${cve.id} - ${cve.descriptions.find(d => d.lang === 'en')?.value.substring(0, 80)}...`);
    });
    console.log('');

    // Test 4: Get recent CVEs
    console.log('📅 Test 4: Getting recent CVEs (last 30 days)...');
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const today = new Date();
    
    const recentResponse = await nvd.getCvesByDateRange(
      thirtyDaysAgo.toISOString().split('T')[0],
      today.toISOString().split('T')[0]
    );
    console.log(`Found ${recentResponse.totalResults} CVEs published in the last 30 days`);
    console.log(`Showing ${recentResponse.vulnerabilities.length} results`);
    
    recentResponse.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
      const cve = vuln.cve;
      const internalCve = NvdWrapper.convertToInternalFormat(cve);
      console.log(`${index + 1}. ${cve.id} - ${internalCve.severity} - Published: ${cve.published.split('T')[0]}`);
    });

  } catch (error) {
    console.error('❌ Error testing NVD API:', error);
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testNvdWrapper();
}

export { testNvdWrapper }; 