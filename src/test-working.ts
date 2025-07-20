import { NvdWrapper } from './services/nvd';

async function workingTest() {
  console.log('🛡️ Testing NVD API v2.0 with correct parameters...\n');

  const nvd = new NvdWrapper();

  try {
    // Test 1: Get a specific CVE (this works)
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
    }
    console.log('');

    // Test 2: Try getting recent CVEs with correct date format
    console.log('📅 Test 2: Getting recent CVEs...');
    const today = new Date();
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    // Format dates as YYYY-MM-DDTHH:mm:ss:mmm UTC
    const startDate = weekAgo.toISOString();
    const endDate = today.toISOString();
    
    console.log(`   Date range: ${startDate} to ${endDate}`);
    
    const recentResponse = await nvd.getCvesByDateRange(startDate, endDate);
    console.log(`✅ Recent CVEs: Found ${recentResponse.totalResults} CVEs in the last week`);
    console.log(`   Showing ${recentResponse.vulnerabilities.length} results`);
    
    if (recentResponse.vulnerabilities.length > 0) {
      recentResponse.vulnerabilities.slice(0, 3).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
        console.log(`      Published: ${cve.published.split('T')[0]}`);
      });
    }
    console.log('');

    // Test 3: Try getting high severity CVEs
    console.log('🚨 Test 3: Getting HIGH severity CVEs...');
    const highSeverityResponse = await nvd.getCvesBySeverity('HIGH', 'v3');
    console.log(`✅ High Severity: Found ${highSeverityResponse.totalResults} HIGH severity CVEs`);
    console.log(`   Showing ${highSeverityResponse.vulnerabilities.length} results`);
    
    if (highSeverityResponse.vulnerabilities.length > 0) {
      highSeverityResponse.vulnerabilities.slice(0, 2).forEach((vuln, index) => {
        const cve = vuln.cve;
        const internalCve = NvdWrapper.convertToInternalFormat(cve);
        console.log(`   ${index + 1}. ${cve.id} - ${internalCve.severity} (CVSS: ${internalCve.cvssScore})`);
        console.log(`      Title: ${internalCve.title.substring(0, 60)}...`);
      });
    }

  } catch (error: any) {
    console.error('❌ Error in working test:', error.message);
  }
}

// Run the test
workingTest(); 