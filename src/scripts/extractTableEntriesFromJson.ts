/*
Single-function converter: NVD 2.0 CVE (the inner `cve` object) → table schema
Schema fields:
  id, sourceIdentifier, published, lastModified, vulnStatus, description (lang:en),
  metricVersion (NA/2.0/3.0/3.1/4.0), source, baseScore:number, vectorString, baseSeverity,
  attackVector, attackComplexity, exploitabilityScore:number, impactScore:number, cweIds (string[])
*/

export enum MetricVersion {
  NA = '',
  V20 = '2.0',
  V30 = '3.0',
  V31 = '3.1',
  V40 = '4.0',
}

// Utility: safe get english description
function getEnglishDescription(cve: any): string {
  const descriptions = cve?.descriptions;
  if (Array.isArray(descriptions)) {
    const en = descriptions.find((d: any) => d?.lang === 'en');
    if (en?.value) return String(en.value);
    const first = descriptions[0]?.value;
    if (first) return String(first);
  }
  return '';
}

// Utility: collect CWE IDs as strings (e.g., ["CWE-79", "CWE-89"]) from weaknesses[][].description[].value
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
  const seen = new Set<string>();
  const uniq: string[] = [];
  for (const id of result) {
    if (!seen.has(id)) {
      seen.add(id);
      uniq.push(id);
    }
  }
  return uniq;
}

// Metric picking
type FlatMetric = {
  metricVersion: MetricVersion;
  source: string;
  baseScore: number;
  vectorString: string;
  baseSeverity: string;
  attackVector: string;
  attackComplexity: string;
  exploitabilityScore: number;
  impactScore: number;
};

function asNumberOrMinusOne(value: any): number {
  const n = typeof value === 'number' ? value : Number.isFinite(value) ? Number(value) : NaN;
  return Number.isFinite(n) ? n : -1;
}

function mapV40(m: any): FlatMetric {
  const d = m?.cvssData || {};
  return {
    metricVersion: MetricVersion.V40,
    source: m?.source ?? '',
    baseScore: asNumberOrMinusOne(d?.baseScore),
    vectorString: d?.vectorString ?? '',
    baseSeverity: d?.baseSeverity ?? '',
    attackVector: d?.attackVector ?? '',
    attackComplexity: d?.attackComplexity ?? '',
    exploitabilityScore: asNumberOrMinusOne(m?.exploitabilityScore),
    impactScore: asNumberOrMinusOne(m?.impactScore),
  };
}

function mapV31(m: any): FlatMetric {
  const d = m?.cvssData || {};
  return {
    metricVersion: MetricVersion.V31,
    source: m?.source ?? '',
    baseScore: asNumberOrMinusOne(d?.baseScore),
    vectorString: d?.vectorString ?? '',
    baseSeverity: d?.baseSeverity ?? '',
    attackVector: d?.attackVector ?? '',
    attackComplexity: d?.attackComplexity ?? '',
    exploitabilityScore: asNumberOrMinusOne(m?.exploitabilityScore),
    impactScore: asNumberOrMinusOne(m?.impactScore),
  };
}

function mapV30(m: any): FlatMetric {
  const d = m?.cvssData || {};
  return {
    metricVersion: MetricVersion.V30,
    source: m?.source ?? '',
    baseScore: asNumberOrMinusOne(d?.baseScore),
    vectorString: d?.vectorString ?? '',
    baseSeverity: d?.baseSeverity ?? '',
    attackVector: d?.attackVector ?? '',
    attackComplexity: d?.attackComplexity ?? '',
    exploitabilityScore: asNumberOrMinusOne(m?.exploitabilityScore),
    impactScore: asNumberOrMinusOne(m?.impactScore),
  };
}

function mapV20(m: any): FlatMetric {
  const d = m?.cvssData || {};
  return {
    metricVersion: MetricVersion.V20,
    source: m?.source ?? '',
    baseScore: asNumberOrMinusOne(d?.baseScore),
    vectorString: d?.vectorString ?? '',
    baseSeverity: m?.baseSeverity ?? '',
    attackVector: d?.accessVector ?? '',
    attackComplexity: d?.accessComplexity ?? '',
    exploitabilityScore: asNumberOrMinusOne(m?.exploitabilityScore),
    impactScore: asNumberOrMinusOne(m?.impactScore),
  };
}

function pickByTypePriority(list: any[]): any | null {
  if (!Array.isArray(list) || list.length === 0) return null;
  const getType = (m: any) => String(m?.type || '').toLowerCase();
  const primary = list.find((m) => getType(m) === 'primary');
  if (primary) return primary;
  const secondary = list.find((m) => getType(m) === 'secondary');
  if (secondary) return secondary;
  return list[0];
}

export type TableEntry = {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  description: string;
  metricVersion: MetricVersion;
  source: string;
  baseScore: number;
  vectorString: string;
  baseSeverity: string;
  attackVector: string;
  attackComplexity: string;
  exploitabilityScore: number;
  impactScore: number;
  cweIds: string[];
  isDdosRelated: boolean;
};

export function buildTableEntryBase(cve: any) {
  return {
    id: cve?.id ?? cve?.cveId ?? '',
    sourceIdentifier: cve?.sourceIdentifier ?? '',
    published: cve?.published ?? '',
    lastModified: cve?.lastModified ?? '',
    vulnStatus: cve?.vulnStatus ?? '',
    description: getEnglishDescription(cve),
    cweIds: getCweIds(cve),
    isDdosRelated: false,
  } as Pick<TableEntry, 'id' | 'sourceIdentifier' | 'published' | 'lastModified' | 'vulnStatus' | 'description' | 'cweIds' | 'isDdosRelated'>;
}

function toTableEntry(base: ReturnType<typeof buildTableEntryBase>, m: FlatMetric): TableEntry {
  return {
    ...base,
    metricVersion: m.metricVersion,
    source: m.source,
    baseScore: m.baseScore,
    vectorString: m.vectorString,
    baseSeverity: m.baseSeverity,
    attackVector: m.attackVector,
    attackComplexity: m.attackComplexity,
    exploitabilityScore: m.exploitabilityScore,
    impactScore: m.impactScore,
  };
}

// Convert one CVE to multiple table entries: one per metric version (entry picked by type priority)
export function extractTableEntriesFromJson(cve: any): TableEntry[] {
  const base = buildTableEntryBase(cve);
  const out: TableEntry[] = [];
  const metrics = cve?.metrics || {};

  if (Array.isArray(metrics.cvssMetricV31) && metrics.cvssMetricV31.length > 0) {
    const picked = pickByTypePriority(metrics.cvssMetricV31);
    if (picked) out.push(toTableEntry(base, mapV31(picked)));
  }
  if (Array.isArray(metrics.cvssMetricV40) && metrics.cvssMetricV40.length > 0) {
    const picked = pickByTypePriority(metrics.cvssMetricV40);
    if (picked) out.push(toTableEntry(base, mapV40(picked)));
  }
  if (Array.isArray(metrics.cvssMetricV30) && metrics.cvssMetricV30.length > 0) {
    const picked = pickByTypePriority(metrics.cvssMetricV30);
    if (picked) out.push(toTableEntry(base, mapV30(picked)));
  }
  if (Array.isArray(metrics.cvssMetricV2) && metrics.cvssMetricV2.length > 0) {
    const picked = pickByTypePriority(metrics.cvssMetricV2);
    if (picked) out.push(toTableEntry(base, mapV20(picked)));
  }

  return out;
}

export function extractTableEntriesFromDataFeedFile(filePath: string): TableEntry[] {
  const fs = require('fs');
  const path = require('path');

  const start = Date.now();
  console.log(`[extract] Reading feed: ${path.resolve(filePath)}`);

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (e: any) {
    console.error(`[extract] Failed to read file: ${e?.message || e}`);
    return [];
  }

  let json: any;
  try {
    json = JSON.parse(raw);
  } catch (e: any) {
    console.error(`[extract] Failed to parse JSON: ${e?.message || e}`);
    return [];
  }

  const vulns: any[] = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : Array.isArray(json) ? json : [];
  if (!Array.isArray(vulns) || vulns.length === 0) {
    console.warn('[extract] No vulnerabilities array found in feed');
    return [];
  }

  console.log(`[extract] Vulnerabilities in feed: ${vulns.length}`);

  const out: TableEntry[] = [];
  let processed = 0;
  for (const v of vulns) {
    const cve = v?.cve ?? v;
    const entries = extractTableEntriesFromJson(cve);
    if (entries && entries.length) {
      out.push(...entries);
    }
    processed++;
    if (processed % 10000 === 0) {
      console.log(`[extract] Processed ${processed}/${vulns.length} CVEs… (entries so far: ${out.length})`);
    }
  }

  const ms = Date.now() - start;
  console.log(`[extract] Done. CVEs processed: ${processed}. Entries: ${out.length}. Time: ${ms}ms`);
  return out;
}