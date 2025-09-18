import { Router } from 'express';
import { CVE } from '../types/cve';
import { getSeveritiesDistribution, getMetricVersionStats, getYearlyCveTrends } from '../queries/getSeveritiesDistribution';
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


// GET all CVEs from SQLite database
router.get('/all', async (req, res) => {
  try {
    // Load all CVE data from the SQLite database
    const { CveSqliteManager } = await import('../scripts/saveToSqlite');
    const manager = new CveSqliteManager('./cve_database.db');
    
    // Get all entries from the database
    const allEntries = await manager.queryEntries({ limit: 10000 }); // Large limit to get all
    
    // Transform database entries to frontend format
    const transformedCves = allEntries.map(entry => ({
      id: entry.id,
      cveId: entry.id,
      title: `CVE ${entry.id}`,
      description: entry.description || 'No description available',
      severity: entry.baseSeverity || 'UNKNOWN',
      cvssScore: entry.baseScore || 0,
      attackVector: entry.attackVector || 'NETWORK',
      affectedProducts: [], // Not in database schema
      publishedDate: entry.published || new Date().toISOString().split('T')[0],
      lastModifiedDate: entry.lastModified || new Date().toISOString().split('T')[0],
      status: entry.vulnStatus === 'Analyzed' ? 'ACTIVE' : 'INVESTIGATING',
      ddosRelated: Boolean(entry.isDdosRelated),
      references: [`https://nvd.nist.gov/vuln/detail/${entry.id}`]
    }));
    
    await manager.close();
    res.json(transformedCves);
  } catch (error) {
    console.error('Error loading CVEs from database:', error);
    res.status(500).json({ error: 'Failed to load CVEs from database' });
  }
});

// GET all CVEs (legacy endpoint)
router.get('/', (req, res) => {
  const metricVersion = req.query.metricVersion as string;
  
  // For now, return all CVEs regardless of metric version
  // In a real implementation, you would filter based on metricVersion
  // This would require querying the database with the specific metric version
  res.json(cves);
});


// GET single CVE by ID
router.get('/:id', (req, res) => {
  const id = req.params.id;
  const cve = cves.find(c => c.id === id);
  
  if (!cve) {
    return res.status(404).json({ error: 'CVE not found' });
  }
  
  res.json(cve);
});

// GET CVE by CVE ID (search functionality)
router.get('/search/:cveId', async (req, res) => {
  try {
    const cveId = req.params.cveId;
    
    // Load CVE data from the SQLite database
    const { CveSqliteManager } = await import('../scripts/saveToSqlite');
    const manager = new CveSqliteManager('./cve_database.db');
    
    // Try different CVE ID formats
    let entries = await manager.queryEntries({ 
      id: cveId,
      limit: 1
    });
    
    // If not found, try with CVE- prefix
    if (entries.length === 0) {
      entries = await manager.queryEntries({ 
        id: `CVE-${cveId}`,
        limit: 1
      });
    }
    
    if (entries.length === 0) {
      // Debug: Let's see what CVE IDs exist in the database
      const allEntries = await manager.queryEntries({ limit: 10 });
      const sampleIds = allEntries.map(e => e.id).slice(0, 5);
      
      await manager.close();
      return res.status(404).json({ 
        success: false, 
        error: `CVE-${cveId} not found in database`,
        debug: {
          searchedFor: [cveId, `CVE-${cveId}`],
          sampleIds: sampleIds
        }
      });
    }
    
    const entry = entries[0];
    
    // Transform database entry to frontend format
    const cveData = {
      id: entry.id,
      cveId: entry.id,
      title: `CVE ${entry.id}`,
      description: entry.description || 'No description available',
      severity: entry.baseSeverity || 'UNKNOWN',
      cvssScore: entry.baseScore || 0,
      attackVector: entry.attackVector || 'NETWORK',
      affectedProducts: [], // Not in database schema
      publishedDate: entry.published || new Date().toISOString().split('T')[0],
      lastModifiedDate: entry.lastModified || new Date().toISOString().split('T')[0],
      status: entry.vulnStatus === 'Analyzed' ? 'ACTIVE' : 'INVESTIGATING',
      ddosRelated: Boolean(entry.isDdosRelated),
      references: [`https://nvd.nist.gov/vuln/detail/${entry.id}`],
      metricVersion: entry.metricVersion || '3.1'
    };
    
    await manager.close();
    res.json({ 
      success: true, 
      cve: cveData 
    });
    
  } catch (error) {
    console.error('Error searching for CVE:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to search for CVE in database' 
    });
  }
});




// GET total CVE count for specific metric version with DDoS ratio
router.get('/stats/count', async (req, res) => {
  try {
    const metricParam = (req.query.metricVersion as string) || '3.1';
    const validVersions = new Set(['2.0', '3.0', '3.1', '4.0']);
    const versionValue = validVersions.has(metricParam) ? metricParam : '3.1';
    
    // Map database values to MetricVersion enum
    const versionMapping: Record<string, MetricVersion> = {
      '2.0': MetricVersion.V20,
      '3.0': MetricVersion.V30,
      '3.1': MetricVersion.V31,
      '4.0': MetricVersion.V40
    };
    
    // Get both DDoS and non-DDoS stats
    const [ddosStats, nonDdosStats] = await Promise.all([
      getMetricVersionStats(versionMapping[versionValue], undefined, true), // DDoS-related
      getMetricVersionStats(versionMapping[versionValue], undefined, false) // Non-DDoS-related
    ]);
    
    const totalCount = ddosStats.totalEntries + nonDdosStats.totalEntries;
    const ddosCount = ddosStats.totalEntries;
    const nonDdosCount = nonDdosStats.totalEntries;
    
    // Calculate ratio
    const ddosRatio = totalCount > 0 ? (ddosCount / totalCount * 100).toFixed(1) : '0.0';
    const nonDdosRatio = totalCount > 0 ? (nonDdosCount / totalCount * 100).toFixed(1) : '0.0';
    
    res.json({ 
      success: true, 
      metricVersion: versionValue, 
      totalCount,
      ddosCount,
      nonDdosCount,
      ddosRatio: parseFloat(ddosRatio),
      nonDdosRatio: parseFloat(nonDdosRatio),
      averageScore: ddosStats.averageScore // Use DDoS average score
    });
  } catch (error: any) {
    console.error('Error getting CVE count:', error);
    res.status(500).json({ success: false, error: error?.message || 'Failed to get CVE count' });
  }
});

// GET severity distribution from SQLite (defaults to CVSS 3.1)
router.get('/stats/severity', async (req, res) => {
  try {
    const metricParam = (req.query.metricVersion as string) || '3.1';
    const validVersions = new Set(['2.0', '3.0', '3.1', '4.0']);
    const versionValue = validVersions.has(metricParam) ? metricParam : '3.1';
    
    // Map database values to MetricVersion enum
    const versionMapping: Record<string, MetricVersion> = {
      '2.0': MetricVersion.V20,
      '3.0': MetricVersion.V30,
      '3.1': MetricVersion.V31,
      '4.0': MetricVersion.V40
    };
    
    const distribution = await getSeveritiesDistribution(versionMapping[versionValue]);
    res.json({ success: true, metricVersion: versionValue, distribution });
  } catch (error: any) {
    console.error('Error getting severity distribution:', error);
    res.status(500).json({ success: false, error: error?.message || 'Failed to get severity distribution' });
  }
});

// GET yearly CVE trends from SQLite (all CVEs, not just DDoS)
router.get('/stats/yearly-trends', async (req, res) => {
  try {
    const metricParam = (req.query.metricVersion as string) || '3.1';
    const validVersions = new Set(['2.0', '3.0', '3.1', '4.0']);
    const versionValue = validVersions.has(metricParam) ? metricParam : '3.1';
    
    // Map database values to MetricVersion enum
    const versionMapping: Record<string, MetricVersion> = {
      '2.0': MetricVersion.V20,
      '3.0': MetricVersion.V30,
      '3.1': MetricVersion.V31,
      '4.0': MetricVersion.V40
    };
    
    const yearlyData = await getYearlyCveTrends(versionMapping[versionValue]);
    res.json({ success: true, metricVersion: versionValue, yearlyData });
  } catch (error: any) {
    console.error('Error getting yearly CVE trends:', error);
    res.status(500).json({ success: false, error: error?.message || 'Failed to get yearly CVE trends' });
  }
});

export default router; 