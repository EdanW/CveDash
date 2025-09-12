/*
Minimal JSON → CSV converter for NVD 2.0 CVE entries
- Accepts a single CVE object, an array of CVE wrappers, or an NVD 2.0 file with `vulnerabilities`.
- Produces one CSV row per CVSS metric instance (v4.0, v3.1, v2.0), adhering to the schema outlined
  in the lower half of src/scripts/jsonExample.json.

Columns:
  id,sourceIdentifier,published,lastModified,vulnStatus,description,metricVersion,source,baseScore,vectorString,baseSeverity,attackVector,attackComplexity,exploitabilityScore,impactScore,cweIds
*/

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
  // De-duplicate while preserving order
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

// Utility: build flat metric rows from any metric collection
function buildMetricRows(cve: any): Array<Record<string, any>> {
  const rows: Array<Record<string, any>> = [];
  const metrics = cve?.metrics || {};

  // v4.0
  if (Array.isArray(metrics.cvssMetricV40)) {
    for (const m of metrics.cvssMetricV40) {
      const d = m?.cvssData || {};
      rows.push({
        metricVersion: '4.0',
        source: m?.source ?? '',
        baseScore: d?.baseScore ?? '',
        vectorString: d?.vectorString ?? '',
        baseSeverity: d?.baseSeverity ?? '',
        attackVector: d?.attackVector ?? '',
        attackComplexity: d?.attackComplexity ?? '',
        exploitabilityScore: m?.exploitabilityScore ?? '', // often absent in v4 examples
        impactScore: m?.impactScore ?? '',
      });
    }
  }

  // v3.1 (sometimes labeled cvssMetricV31)
  if (Array.isArray(metrics.cvssMetricV31)) {
    for (const m of metrics.cvssMetricV31) {
      const d = m?.cvssData || {};
      rows.push({
        metricVersion: '3.1',
        source: m?.source ?? '',
        baseScore: d?.baseScore ?? '',
        vectorString: d?.vectorString ?? '',
        baseSeverity: d?.baseSeverity ?? '',
        attackVector: d?.attackVector ?? '',
        attackComplexity: d?.attackComplexity ?? '',
        exploitabilityScore: m?.exploitabilityScore ?? '',
        impactScore: m?.impactScore ?? '',
      });
    }
  }

  // v3.0 (occasionally appears as cvssMetricV30 in some datasets)
  if (Array.isArray(metrics.cvssMetricV30)) {
    for (const m of metrics.cvssMetricV30) {
      const d = m?.cvssData || {};
      rows.push({
        metricVersion: '3.0',
        source: m?.source ?? '',
        baseScore: d?.baseScore ?? '',
        vectorString: d?.vectorString ?? '',
        baseSeverity: d?.baseSeverity ?? '',
        attackVector: d?.attackVector ?? '',
        attackComplexity: d?.attackComplexity ?? '',
        exploitabilityScore: m?.exploitabilityScore ?? '',
        impactScore: m?.impactScore ?? '',
      });
    }
  }

  // v2.0
  if (Array.isArray(metrics.cvssMetricV2)) {
    for (const m of metrics.cvssMetricV2) {
      const d = m?.cvssData || {};
      rows.push({
        metricVersion: '2.0',
        source: m?.source ?? '',
        baseScore: d?.baseScore ?? '',
        vectorString: d?.vectorString ?? '',
        baseSeverity: m?.baseSeverity ?? '', // in v2, severity often sits next to cvssData
        // map legacy names
        attackVector: d?.accessVector ?? '',
        attackComplexity: d?.accessComplexity ?? '',
        exploitabilityScore: m?.exploitabilityScore ?? '',
        impactScore: m?.impactScore ?? '',
      });
    }
  }

  return rows;
}

// CSV helpers
function csvEscape(value: any): string {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function toCsv(rows: Array<Record<string, any>>, header: string[]): string {
  const lines: string[] = [];
  lines.push(header.join(','));
  for (const row of rows) {
    const line = header.map((key) => csvEscape(row[key])).join(',');
    lines.push(line);
  }
  return lines.join('\n');
}

// Main converter: one CSV row per metric instance
export function convertCveToCsvRows(cveWrapper: any): Array<Record<string, any>> {
  const cve = cveWrapper?.cve ?? cveWrapper; // accept either wrapper or bare cve
  const base = {
    id: cve?.id ?? cve?.cveId ?? '',
    sourceIdentifier: cve?.sourceIdentifier ?? '',
    published: cve?.published ?? '',
    lastModified: cve?.lastModified ?? '',
    vulnStatus: cve?.vulnStatus ?? '',
    description: getEnglishDescription(cve),
    cweIds: getCweIds(cve).join('|'),
  };

  const metricRows = buildMetricRows(cve);
  if (metricRows.length === 0) {
    // Still emit a row with empty metric fields
    return [{
      ...base,
      metricVersion: '',
      source: '',
      baseScore: '',
      vectorString: '',
      baseSeverity: '',
      attackVector: '',
      attackComplexity: '',
      exploitabilityScore: '',
      impactScore: '',
    }];
  }

  return metricRows.map((m) => ({ ...base, ...m }));
}

export function convertManyToCsvRows(input: any): Array<Record<string, any>> {
  // Accept: array of wrappers, single wrapper, or NVD 2.0 file { vulnerabilities: [{ cve }] }
  if (Array.isArray(input)) {
    return input.flatMap((item) => convertCveToCsvRows(item));
  }
  if (input && Array.isArray(input.vulnerabilities)) {
    return input.vulnerabilities.flatMap((v: any) => convertCveToCsvRows(v));
  }
  return convertCveToCsvRows(input);
}

export function convertToCsv(input: any): string {
  const header = [
    'id',
    'sourceIdentifier',
    'published',
    'lastModified',
    'vulnStatus',
    'description',
    'metricVersion',
    'source',
    'baseScore',
    'vectorString',
    'baseSeverity',
    'attackVector',
    'attackComplexity',
    'exploitabilityScore',
    'impactScore',
    'cweIds',
  ];
  const rows = convertManyToCsvRows(input);
  return toCsv(rows, header);
}

// CLI: node dist/scripts/jsonToCvs.js <pathToJson>
if (require.main === module) {
  const fs = require('fs');
  const path = process.argv[2];
  if (!path) {
    console.error('Usage: ts-node src/scripts/jsonToCvs.ts <pathToJson>');
    process.exit(1);
  }
  try {
    const text = fs.readFileSync(path, 'utf8');
    const json = JSON.parse(text);
    const csv = convertToCsv(json);
    process.stdout.write(csv + '\n');
  } catch (err) {
    const msg = err && typeof err === 'object' && 'message' in (err as any) ? (err as any).message : String(err);
    console.error('Failed to convert:', msg);
    process.exit(1);
  }
}
