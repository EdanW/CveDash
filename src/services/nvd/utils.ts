import { NvdCve } from './types';

/**
 * Convert NVD CVE to our internal CVE format
 * @param nvdCve - NVD CVE object
 * @returns CVE object in our format
 */
export function convertToInternalFormat(nvdCve: NvdCve): any {
  const cvssScore = nvdCve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
                   nvdCve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
                   nvdCve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;

  const severity = nvdCve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
                  nvdCve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
                  nvdCve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseSeverity || 'UNKNOWN';

  return {
    id: nvdCve.id,
    cveId: nvdCve.id,
    title: nvdCve.descriptions.find(d => d.lang === 'en')?.value || 'No description available',
    description: nvdCve.descriptions.find(d => d.lang === 'en')?.value || 'No description available',
    severity: severity.toUpperCase(),
    cvssScore,
    attackVector: nvdCve.metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector || 'UNKNOWN',
    affectedProducts: nvdCve.configurations?.flatMap(config => 
      config.nodes.flatMap(node => 
        node.cpeMatch?.map(match => match.criteria) || []
      )
    ) || [],
    publishedDate: nvdCve.published,
    lastModifiedDate: nvdCve.lastModified,
    status: nvdCve.vulnStatus === 'Analyzed' ? 'ACTIVE' : 'INVESTIGATING',
    ddosRelated: isDdosRelated(nvdCve),
    references: nvdCve.references?.map(ref => ref.url) || []
  };
}

/**
 * Check if a CVE is DDoS-related based on its description and keywords
 * @param nvdCve - NVD CVE object
 * @returns boolean
 */
export function isDdosRelated(nvdCve: NvdCve): boolean {
  const description = nvdCve.descriptions.find(d => d.lang === 'en')?.value.toLowerCase() || '';
  const ddosKeywords = [
    'ddos', 'denial of service', 'dos', 'flood', 'amplification', 'syn flood', 
    'udp flood', 'http flood', 'dns amplification', 'ntp amplification',
    'rate limiting', 'connection exhaustion', 'resource exhaustion'
  ];
  
  return ddosKeywords.some(keyword => description.includes(keyword));
}

/**
 * Extract CVSS score from NVD CVE metrics
 * @param nvdCve - NVD CVE object
 * @returns CVSS score or 0 if not available
 */
export function extractCvssScore(nvdCve: NvdCve): number {
  return nvdCve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 
         nvdCve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || 
         nvdCve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
}

/**
 * Extract severity from NVD CVE metrics
 * @param nvdCve - NVD CVE object
 * @returns Severity string
 */
export function extractSeverity(nvdCve: NvdCve): string {
  return nvdCve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
         nvdCve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ||
         nvdCve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseSeverity || 'UNKNOWN';
} 