import axios from 'axios';

async function debugApi() {
  console.log('🔍 Debugging NVD API calls...\n');

  const baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  try {
    // Test 1: Direct API call to understand the structure
    console.log('📋 Test 1: Direct API call with minimal parameters...');
    
    const response1 = await axios.get(baseUrl, {
      params: {
        resultsPerPage: 1
      },
      headers: {
        'User-Agent': 'CveDash/1.0'
      }
    });
    
    console.log('✅ Direct call successful!');
    console.log(`   Status: ${response1.status}`);
    console.log(`   Total Results: ${response1.data.totalResults}`);
    console.log(`   Format: ${response1.data.format}`);
    console.log(`   Version: ${response1.data.version}`);
    console.log('');

    // Test 2: Try keyword search with different parameter names
    console.log('📋 Test 2: Testing keyword search parameters...');
    
    // Try different parameter variations
    const searchParams = [
      { keywordSearch: 'vulnerability' },
      { keywordSearch: 'vulnerability', keywordExactMatch: false },
      { virtualMatchString: 'vulnerability' },
      { keywordSearch: 'vulnerability', resultsPerPage: 5 }
    ];

    for (let i = 0; i < searchParams.length; i++) {
      try {
        console.log(`   Trying params ${i + 1}:`, searchParams[i]);
        const response = await axios.get(baseUrl, {
          params: searchParams[i],
          headers: {
            'User-Agent': 'CveDash/1.0'
          }
        });
        
        console.log(`   ✅ Success! Found ${response.data.totalResults} results`);
        break;
      } catch (error: any) {
        console.log(`   ❌ Failed: ${error.response?.status} - ${error.response?.statusText}`);
      }
    }
    console.log('');

    // Test 3: Check what parameters are actually supported
    console.log('📋 Test 3: Testing individual parameters...');
    
    const testParams = [
      'keywordSearch',
      'virtualMatchString', 
      'keywordExactMatch',
      'resultsPerPage',
      'startIndex'
    ];

    for (const param of testParams) {
      try {
        const testValue = param === 'keywordSearch' ? 'test' : 
                         param === 'virtualMatchString' ? 'test' :
                         param === 'keywordExactMatch' ? false :
                         param === 'resultsPerPage' ? 1 : 0;
        
        const response = await axios.get(baseUrl, {
          params: { [param]: testValue },
          headers: {
            'User-Agent': 'CveDash/1.0'
          }
        });
        
        console.log(`   ✅ ${param}: Supported`);
      } catch (error: any) {
        console.log(`   ❌ ${param}: Not supported (${error.response?.status})`);
      }
    }

  } catch (error: any) {
    console.error('❌ Error in debug:', error.message);
  }
}

// Run the debug
debugApi(); 