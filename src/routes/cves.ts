import { Router } from 'express';
import { CVE } from '../types/cve';
import { NvdWrapper } from '../services/nvd';
import { getSeveritiesDistribution } from '../queries/getSeveritiesDistribution';
import { MetricVersion } from '../scripts/extractTableEntriesFromJson';

const router = Router();

// In-memory CVE database with DDoS-related vulnerabilities
let cves: CVE[] = [
  {
    id: '1',
    cveId: 'CVE-2023-1234',
    title: 'DDoS Amplification Vulnerability in DNS Server',
    description: 'A vulnerability in DNS server implementation allows attackers to perform DNS amplification attacks, potentially causing large-scale DDoS attacks.',
    severity: 'HIGH',
    cvssScore: 8.5,
    attackVector: 'NETWORK',
    affectedProducts: ['DNS Server v2.1', 'DNS Server v2.2'],
    publishedDate: '2023-01-15',
    lastModifiedDate: '2023-01-20',
    status: 'ACTIVE',
    ddosRelated: true,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-1234',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234'
    ]
  },
  {
    id: '2',
    cveId: 'CVE-2023-5678',
    title: 'HTTP Flood Attack Vulnerability in Web Server',
    description: 'Web server fails to properly rate-limit HTTP requests, making it vulnerable to HTTP flood DDoS attacks.',
    severity: 'MEDIUM',
    cvssScore: 6.5,
    attackVector: 'NETWORK',
    affectedProducts: ['WebServer Pro v3.0', 'WebServer Pro v3.1'],
    publishedDate: '2023-02-10',
    lastModifiedDate: '2023-02-15',
    status: 'PATCHED',
    ddosRelated: true,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-5678'
    ]
  },
  {
    id: '3',
    cveId: 'CVE-2023-9012',
    title: 'SYN Flood Protection Bypass',
    description: 'Network firewall fails to properly handle SYN flood attacks, allowing attackers to exhaust connection pools.',
    severity: 'CRITICAL',
    cvssScore: 9.1,
    attackVector: 'NETWORK',
    affectedProducts: ['Firewall Enterprise v4.0'],
    publishedDate: '2023-03-05',
    lastModifiedDate: '2023-03-10',
    status: 'INVESTIGATING',
    ddosRelated: true,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-9012',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9012'
    ]
  },
  {
    id: '4',
    cveId: 'CVE-2023-3456',
    title: 'UDP Flood Attack in Network Protocol',
    description: 'Network protocol implementation vulnerable to UDP flood attacks, causing service disruption.',
    severity: 'HIGH',
    cvssScore: 7.8,
    attackVector: 'NETWORK',
    affectedProducts: ['NetworkProtocol v1.5', 'NetworkProtocol v1.6'],
    publishedDate: '2023-04-12',
    lastModifiedDate: '2023-04-18',
    status: 'ACTIVE',
    ddosRelated: true,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-3456'
    ]
  },
  {
    id: '5',
    cveId: 'CVE-2023-7890',
    title: 'Application Layer DDoS in API Gateway',
    description: 'API gateway lacks proper rate limiting and request validation, making it vulnerable to application layer DDoS attacks.',
    severity: 'MEDIUM',
    cvssScore: 6.2,
    attackVector: 'NETWORK',
    affectedProducts: ['APIGateway v2.0'],
    publishedDate: '2023-05-20',
    lastModifiedDate: '2023-05-25',
    status: 'PATCHED',
    ddosRelated: true,
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-7890'
    ]
  }
];

let nextId = 6;

// GET all CVEs
router.get('/', (req, res) => {
  res.json(cves);
});

// GET random CVE from NVD API
router.get('/random/nvd', async (req, res) => {
  try {
    const nvd = new NvdWrapper();
    
    // Get recent CVEs (last 30 days) to ensure we get valid CVEs
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const today = new Date();
    
    const response = await nvd.getCvesByDateRange(
      thirtyDaysAgo.toISOString(),
      today.toISOString()
    );
    
    if (response.vulnerabilities.length === 0) {
      return res.status(404).json({ error: 'No recent CVEs found' });
    }
    
    // Pick a random CVE from the results
    const randomIndex = Math.floor(Math.random() * Math.min(response.vulnerabilities.length, 100));
    const randomVuln = response.vulnerabilities[randomIndex];
    
    // Convert to our internal format
    const internalCve = NvdWrapper.convertToInternalFormat(randomVuln.cve);
    
    res.json({
      success: true,
      message: 'Random CVE fetched from NVD API',
      cve: internalCve,
      apiInfo: {
        totalResults: response.totalResults,
        resultsPerPage: response.resultsPerPage,
        timestamp: response.timestamp
      }
    });
    
  } catch (error: any) {
    console.error('Error fetching random CVE:', error);
    res.status(500).json({ 
      error: 'Failed to fetch random CVE from NVD API',
      details: error.message 
    });
  }
});

// GET single CVE
router.get('/:id', (req, res) => {
  const id = req.params.id;
  const cve = cves.find(c => c.id === id);
  
  if (!cve) {
    return res.status(404).json({ error: 'CVE not found' });
  }
  
  res.json(cve);
});

// POST new CVE
router.post('/', (req, res) => {
  const { cveId, title, description, severity, cvssScore, attackVector, affectedProducts, publishedDate, lastModifiedDate, status, ddosRelated, references } = req.body;
  
  if (!cveId || !title || !description || !severity || cvssScore === undefined || !attackVector || !affectedProducts || !publishedDate || !lastModifiedDate || !status || ddosRelated === undefined || !references) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const newCVE: CVE = {
    id: nextId.toString(),
    cveId,
    title,
    description,
    severity,
    cvssScore: parseFloat(cvssScore),
    attackVector,
    affectedProducts: Array.isArray(affectedProducts) ? affectedProducts : [affectedProducts],
    publishedDate,
    lastModifiedDate,
    status,
    ddosRelated: Boolean(ddosRelated),
    references: Array.isArray(references) ? references : [references]
  };
  
  cves.push(newCVE);
  nextId++;
  res.status(201).json(newCVE);
});

// PUT update CVE
router.put('/:id', (req, res) => {
  const id = req.params.id;
  const cveIndex = cves.findIndex(c => c.id === id);
  
  if (cveIndex === -1) {
    return res.status(404).json({ error: 'CVE not found' });
  }
  
  const { cveId, title, description, severity, cvssScore, attackVector, affectedProducts, publishedDate, lastModifiedDate, status, ddosRelated, references } = req.body;
  
  cves[cveIndex] = {
    ...cves[cveIndex],
    cveId: cveId || cves[cveIndex].cveId,
    title: title || cves[cveIndex].title,
    description: description || cves[cveIndex].description,
    severity: severity || cves[cveIndex].severity,
    cvssScore: cvssScore !== undefined ? parseFloat(cvssScore) : cves[cveIndex].cvssScore,
    attackVector: attackVector || cves[cveIndex].attackVector,
    affectedProducts: affectedProducts || cves[cveIndex].affectedProducts,
    publishedDate: publishedDate || cves[cveIndex].publishedDate,
    lastModifiedDate: lastModifiedDate || cves[cveIndex].lastModifiedDate,
    status: status || cves[cveIndex].status,
    ddosRelated: ddosRelated !== undefined ? Boolean(ddosRelated) : cves[cveIndex].ddosRelated,
    references: references || cves[cveIndex].references
  };
  
  res.json(cves[cveIndex]);
});

// DELETE CVE
router.delete('/:id', (req, res) => {
  const id = req.params.id;
  const cveIndex = cves.findIndex(c => c.id === id);
  
  if (cveIndex === -1) {
    return res.status(404).json({ error: 'CVE not found' });
  }
  
  const deletedCVE = cves.splice(cveIndex, 1)[0];
  res.json(deletedCVE);
});

// GET severity distribution from SQLite (defaults to CVSS 3.1)
router.get('/stats/severity', async (req, res) => {
  try {
    const metricParam = (req.query.metricVersion as string) || 'V31';
    const validVersions = new Set(['V20', 'V30', 'V31', 'V40']);
    const versionKey = validVersions.has(metricParam) ? (metricParam as keyof typeof MetricVersion) : 'V31';
    const distribution = await getSeveritiesDistribution(MetricVersion[versionKey]);
    res.json({ success: true, metricVersion: versionKey, distribution });
  } catch (error: any) {
    console.error('Error getting severity distribution:', error);
    res.status(500).json({ success: false, error: error?.message || 'Failed to get severity distribution' });
  }
});

export default router; 