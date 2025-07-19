export interface CVE {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssScore: number;
  attackVector: string;
  affectedProducts: string[];
  publishedDate: string;
  lastModifiedDate: string;
  status: 'ACTIVE' | 'PATCHED' | 'INVESTIGATING';
  ddosRelated: boolean;
  references: string[];
} 