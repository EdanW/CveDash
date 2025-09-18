/**
 * DDoS Detection Utility for CVE Analysis
 * Analyzes CVE data to determine if a vulnerability is DDoS-related
 */

/**
 * Detects if a CVE is related to DDoS attacks
 * @param cve The CVE object from NVD data
 * @returns true if the CVE appears to be DDoS-related, false otherwise
 */
export function detectDdosRelated(cve: any): boolean {
  try {
    // Get English description
    const description = getEnglishDescription(cve);
    
    // Get CWE IDs
    const cweIds = getCweIds(cve);
    
    // Get references for additional context
    const references = getReferences(cve);
    
    // Check for DDoS-related keywords in description
    const hasKeywords = checkDdosKeywords(description);
    
    // Check for DDoS-related CWE IDs
    const hasDdosCwe = checkDdosCweIds(cweIds);
    
    // Check references for DDoS indicators
    const hasReferenceIndicators = checkReferenceIndicators(references);
    
    // Check attack vector indicators
    const hasAttackVectorIndicators = checkAttackVectorIndicators(cve);
    
    // Return true if any indicator is found
    return hasKeywords || hasDdosCwe || hasReferenceIndicators || hasAttackVectorIndicators;
    
  } catch (error) {
    console.warn(`Error in DDoS detection for CVE ${cve?.id || 'unknown'}:`, error);
    return false; // Default to false if analysis fails
  }
}

/**
 * Extract English description from CVE
 */
function getEnglishDescription(cve: any): string {
  const descriptions = cve?.descriptions;
  if (Array.isArray(descriptions)) {
    const en = descriptions.find((d: any) => d?.lang === 'en');
    if (en?.value) return String(en.value).toLowerCase();
    const first = descriptions[0]?.value;
    if (first) return String(first).toLowerCase();
  }
  return '';
}

/**
 * Extract CWE IDs from CVE weaknesses
 */
function getCweIds(cve: any): string[] {
  const weaknesses = cve?.weaknesses;
  const result: string[] = [];
  if (Array.isArray(weaknesses)) {
    for (const w of weaknesses) {
      const descs = w?.description;
      if (Array.isArray(descs)) {
        for (const d of descs) {
          if (typeof d?.value === 'string' && d.value) {
            result.push(d.value);
          }
        }
      }
    }
  }
  return result;
}

/**
 * Extract references from CVE
 */
function getReferences(cve: any): string[] {
  const references = cve?.references;
  const result: string[] = [];
  if (Array.isArray(references)) {
    for (const ref of references) {
      if (ref?.url) result.push(String(ref.url).toLowerCase());
      if (ref?.name) result.push(String(ref.name).toLowerCase());
    }
  }
  return result;
}

/**
 * Check for DDoS-related keywords in description
 */
function checkDdosKeywords(description: string): boolean {
  const ddosKeywords = [
    // Direct DDoS terms
    'ddos', 'distributed denial of service', 'denial of service', 'dos attack',
    
    // Attack types
    'flood attack', 'flooding', 'amplification attack', 'reflection attack',
    'volumetric attack', 'protocol attack', 'application layer attack',
    
    // Specific attack methods
    'syn flood', 'udp flood', 'icmp flood', 'http flood', 'slowloris',
    'ping of death', 'smurf attack', 'fraggle attack', 'teardrop attack',
    
    // Resource exhaustion
    'resource exhaustion', 'memory exhaustion', 'cpu exhaustion',
    'bandwidth consumption', 'connection exhaustion',
    
    // Service availability
    'service unavailable', 'service disruption', 'availability impact',
    'crash the service', 'hang the system', 'system unavailable',
    
    // Amplification vectors
    'ntp amplification', 'dns amplification', 'memcached amplification',
    'ssdp amplification', 'chargen amplification',
    
    // Botnet related
    'botnet', 'zombie network', 'command and control', 'c&c server'
  ];
  
  return ddosKeywords.some(keyword => description.includes(keyword));
}

/**
 * Check for DDoS-related CWE IDs
 */
function checkDdosCweIds(cweIds: string[]): boolean {
  const ddosCweIds = [
    // Resource management issues
    'CWE-400', // Uncontrolled Resource Consumption
    'CWE-770', // Allocation of Resources Without Limits or Throttling
    'CWE-399', // Resource Management Errors
    'CWE-769', // Uncontrolled File Descriptor Consumption
    'CWE-771', // Missing Reference to Active Allocated Resource
    'CWE-772', // Missing Release of Resource after Effective Lifetime
    
    // Availability issues
    'CWE-404', // Improper Resource Shutdown or Release
    'CWE-405', // Asymmetric Resource Consumption (Amplification)
    'CWE-730', // OWASP Top Ten 2004 Category A9 - Denial of Service
    
    // Input validation that can lead to DoS
    'CWE-20',  // Improper Input Validation
    'CWE-119', // Improper Restriction of Operations within the Bounds of a Memory Buffer
    'CWE-190', // Integer Overflow or Wraparound
    'CWE-125', // Out-of-bounds Read
    'CWE-787', // Out-of-bounds Write
    
    // Protocol-specific issues
    'CWE-834', // Excessive Iteration
    'CWE-835', // Loop with Unreachable Exit Condition ('Infinite Loop')
    'CWE-674', // Uncontrolled Recursion
    
    // Network-related
    'CWE-406', // Insufficient Control of Network Message Volume (Network Amplification)
    'CWE-407', // Inefficient Algorithmic Complexity
    'CWE-410', // Insufficient Resource Pool
  ];
  
  return cweIds.some(cweId => ddosCweIds.includes(cweId));
}

/**
 * Check references for DDoS indicators
 */
function checkReferenceIndicators(references: string[]): boolean {
  const ddosReferenceKeywords = [
    'ddos', 'denial of service', 'dos', 'flood', 'amplification',
    'botnet', 'attack vector', 'vulnerability disclosure', 'exploit',
    'security advisory', 'cve details'
  ];
  
  return references.some(ref => 
    ddosReferenceKeywords.some(keyword => ref.includes(keyword))
  );
}

/**
 * Check attack vector indicators in CVE metrics
 */
function checkAttackVectorIndicators(cve: any): boolean {
  const metrics = cve?.metrics || {};
  
  // Check all CVSS versions for network attack vector
  const allMetrics = [
    ...(metrics.cvssMetricV31 || []),
    ...(metrics.cvssMetricV40 || []),
    ...(metrics.cvssMetricV30 || []),
    ...(metrics.cvssMetricV2 || [])
  ];
  
  for (const metric of allMetrics) {
    const cvssData = metric?.cvssData;
    if (cvssData) {
      // Network attack vector is common for DDoS
      if (cvssData.attackVector === 'NETWORK' || cvssData.accessVector === 'NETWORK') {
        // High availability impact suggests potential for DoS
        if (cvssData.availabilityImpact === 'HIGH' || cvssData.availabilityImpact === 'COMPLETE') {
          return true;
        }
      }
    }
  }
  
  return false;
}

/**
 * Get detailed analysis of why a CVE was flagged as DDoS-related
 * Useful for debugging and validation
 */
export function getDdosAnalysisDetails(cve: any): {
  isDdosRelated: boolean;
  reasons: string[];
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
} {
  const reasons: string[] = [];
  let confidence: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  
  try {
    const description = getEnglishDescription(cve);
    const cweIds = getCweIds(cve);
    const references = getReferences(cve);
    
    if (checkDdosKeywords(description)) {
      reasons.push('DDoS-related keywords found in description');
      confidence = 'HIGH';
    }
    
    if (checkDdosCweIds(cweIds)) {
      reasons.push(`DDoS-related CWE IDs found: ${cweIds.join(', ')}`);
      if (confidence === 'LOW') confidence = 'MEDIUM';
    }
    
    if (checkReferenceIndicators(references)) {
      reasons.push('DDoS indicators found in references');
      if (confidence === 'LOW') confidence = 'MEDIUM';
    }
    
    if (checkAttackVectorIndicators(cve)) {
      reasons.push('Network attack vector with high availability impact');
      if (confidence === 'LOW') confidence = 'MEDIUM';
    }
    
    const isDdosRelated = reasons.length > 0;
    
    return {
      isDdosRelated,
      reasons,
      confidence
    };
    
  } catch (error) {
    return {
      isDdosRelated: false,
      reasons: [`Analysis failed: ${error}`],
      confidence: 'LOW'
    };
  }
}
