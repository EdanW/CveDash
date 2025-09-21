#!/usr/bin/env -S node --enable-source-maps
/**
 * detect-ddos.ts
 * CLI: flag DDoS-related CVEs from an NVD 2.0 JSON file.
 *
 * Usage:
 *   ts-node detect-ddos.ts nvd.json [--min medium|high] [--reasons] [--json]
 *   npx tsx detect-ddos.ts nvd.json --min high --reasons
 *   # Or compile with tsc then: node detect-ddos.js nvd.json --json
 */

type Confidence = 'LOW'|'MEDIUM'|'HIGH';

type NormCvss = {
  av?: 'NETWORK'|'ADJACENT'|'LOCAL'|'PHYSICAL';
  ac?: 'LOW'|'HIGH'|'L'|'H';
  ui?: 'NONE'|'REQUIRED'|'N'|'R';
  pr?: 'NONE'|'LOW'|'HIGH'|'N'|'L'|'H';
  a?:  'NONE'|'LOW'|'HIGH'|'COMPLETE'|'N'|'L'|'H';   // v4 VA → a
  c?:  'NONE'|'LOW'|'HIGH'|'COMPLETE'|'N'|'L'|'H';   // v4 VC → c
  i?:  'NONE'|'LOW'|'HIGH'|'COMPLETE'|'N'|'L'|'H';   // v4 VI → i
};

type DdosAnalysis = {
  isDdosRelated: boolean;
  reasons: string[];
  confidence: Confidence;
};

// ---------------- CLI ----------------

function confPass(a: Confidence, min: Confidence): boolean {
  const rank = { LOW: 0, MEDIUM: 1, HIGH: 2 } as const;
  return rank[a] >= rank[min];
}

async function runCli() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: detect-ddos.ts <nvd.json> [--min medium|high] [--reasons] [--json]');
    process.exit(2);
  }
  const file = args[0];
  const minFlagIdx = args.indexOf('--min');
  const minConf: Confidence = (minFlagIdx >= 0 ? String(args[minFlagIdx + 1] || '').toUpperCase() : 'LOW') as Confidence;
  const wantReasons = args.includes('--reasons');
  const wantJsonOut = args.includes('--json');

  const raw = await import('node:fs').then(fs => fs.readFileSync(file, 'utf8'));
  const data = JSON.parse(raw);

  // NVD 2.0 structure: { vulnerabilities: [ { cve: {...} }, ... ] }
  const items: any[] =
    Array.isArray(data?.vulnerabilities) ? data.vulnerabilities :
    Array.isArray(data) ? data : [];

  const results: any[] = [];
  for (const it of items) {
    const cve = it?.cve ?? it;
    const id = cve?.id || cve?.cve?.id || 'UNKNOWN';
    const analysis = getDdosAnalysisDetails(cve);
    const passed = analysis.isDdosRelated && confPass(analysis.confidence, (minConf || 'LOW') as Confidence);

    if (wantJsonOut) {
      results.push({
        id,
        ddos: passed,
        confidence: analysis.confidence,
        ...(wantReasons ? { reasons: analysis.reasons } : {}),
      });
    } else {
      if (passed) {
        console.log(`${id}\tddos=true\tconfidence=${analysis.confidence}`);
        if (wantReasons) for (const r of analysis.reasons) console.log(`  - ${r}`);
      } else if (wantReasons) {
        console.log(`${id}\tddos=false\tconfidence=${analysis.confidence}`);
        for (const r of analysis.reasons) console.log(`  - ${r}`);
      }
    }
  }

  if (wantJsonOut) {
    console.log(JSON.stringify(results, null, 2));
  }
}

// Only run CLI when this file is executed directly
if (require.main === module) {
  runCli().catch(err => {
    console.error('Error:', err?.message || err);
    process.exit(1);
  });
}

// -------------- Detector (strict) --------------

export function detectDdosRelated(cve: any): boolean {
  const d = getDdosAnalysisDetails(cve);
  return d.isDdosRelated && d.confidence !== 'LOW';
}

function extractNormCvss(cve: any): NormCvss[] {
  const m = cve?.metrics || {};
  const all: any[] = [
    ...(m.cvssMetricV40 || []),
    ...(m.cvssMetricV31 || []),
    ...(m.cvssMetricV30 || []),
    ...(m.cvssMetricV2  || []),
  ];
  const out: NormCvss[] = [];
  
  // Helper functions to safely cast to expected types
  const parseAv = (v: any): NormCvss['av'] => {
    const val = String(v ?? '').toUpperCase();
    if (['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'].includes(val)) {
      return val as NormCvss['av'];
    }
    return undefined;
  };
  
  const parseAc = (v: any): NormCvss['ac'] => {
    const val = String(v ?? '').toUpperCase();
    if (['LOW', 'HIGH', 'L', 'H'].includes(val)) {
      return val as NormCvss['ac'];
    }
    return undefined;
  };
  
  const parseUi = (v: any): NormCvss['ui'] => {
    const val = String(v ?? '').toUpperCase();
    if (['NONE', 'REQUIRED', 'N', 'R'].includes(val)) {
      return val as NormCvss['ui'];
    }
    return undefined;
  };
  
  const parsePr = (v: any): NormCvss['pr'] => {
    const val = String(v ?? '').toUpperCase();
    if (['NONE', 'LOW', 'HIGH', 'N', 'L', 'H'].includes(val)) {
      return val as NormCvss['pr'];
    }
    return undefined;
  };
  
  const parseImpact = (v: any): NormCvss['a'] => {
    const val = String(v ?? '').toUpperCase();
    if (['NONE', 'LOW', 'HIGH', 'COMPLETE', 'N', 'L', 'H'].includes(val)) {
      return val as NormCvss['a'];
    }
    return undefined;
  };
  
  for (const x of all) {
    const d = x?.cvssData || {};
    out.push({
      av: parseAv(d.attackVector || d.accessVector || d.av),
      ac: parseAc(d.attackComplexity || d.accessComplexity || d.ac),
      ui: parseUi(d.userInteraction || d.ui),
      pr: parsePr(d.privilegesRequired || d.pr),
      a:  parseImpact(d.availabilityImpact || d.va),
      c:  parseImpact(d.confidentialityImpact || d.vc),
      i:  parseImpact(d.integrityImpact || d.vi),
    });
  }
  return out;
}

// Gate: network/adjacent + high availability + low C/I; bonus for PR:N, UI:N, AC:L
function metricsPassGate(norms: NormCvss[]): {passed: boolean; bonus: number; reasons: string[]} {
  const reasons: string[] = [];
  let passed = false;
  let bonus = 0;

  for (const n of norms) {
    const avOK = n.av === 'NETWORK' || n.av === 'ADJACENT';
    const aHigh = n.a === 'HIGH' || n.a === 'COMPLETE' || n.a === 'H';
    const cLow  = !n.c || n.c === 'NONE' || n.c === 'LOW' || n.c === 'N' || n.c === 'L';
    const iLow  = !n.i || n.i === 'NONE' || n.i === 'LOW' || n.i === 'N' || n.i === 'L';
    if (avOK && aHigh && cLow && iLow) {
      passed = true;
      reasons.push(`CVSS gate: AV=${n.av}, A=${n.a || 'N/A'}, C=${n.c || 'N/A'}, I=${n.i || 'N/A'}`);
      if (n.pr === 'NONE' || n.pr === 'N') { bonus += 1; reasons.push('PR:N'); }
      if (n.ui === 'NONE' || n.ui === 'N') { bonus += 1; reasons.push('UI:N'); }
      if (n.ac === 'LOW'  || n.ac === 'L') { bonus += 1; reasons.push('AC:L'); }
      break;
    }
  }
  return { passed, bonus, reasons };
}

// Description lexicon: amplification/reflection/spoofing/protocol hints (NO "denial of service")
function hasAmplificationLexicon(text: string): boolean {
  if (!text) return false;
  const kw = [
    'amplification','amplify','reflect','reflection','reflected','drdos',
    'spoof','spoofed','spoofing','open resolver','traffic amplification',
    'packet amplification','bandwidth amplification','bandwidth exhaustion','ddos', 'distributed denial of service', 'distributed denial', 'ddos attack', 'ddos attack vector', 'ddos attack surface', 'ddos attack vector', 'ddos attack surface', 'ddos attack vector', 'ddos attack surface',
    // DDoS-able protocols/features
    'ntp','monlist','dns','open dns resolver','mdns','ssdp','ws-discovery',
    'cldap','ldap','snmp','chargen','qotd','mssql','memcached','coap',
    'ripv1','nbns','sntp'
  ];
  const t = text.toLowerCase();
  return kw.some(k => t.includes(k));
}

// Negative hints for generic/local DoS or non-DDoS web vulns
function hasNegativeHints(text: string): boolean {
  if (!text) return false;
  const neg = [
    'sql injection','sql-injection','sqli',
    'cross-site scripting','xss',
    'null pointer','use-after-free','out-of-bounds','oob read','oob write',
    'integer overflow','infinite loop','resource exhaustion','memory exhaustion',
    'cpu exhaustion','hang','crash','kernel panic','local user','authenticated user'
  ];
  const t = text.toLowerCase();
  return neg.some(k => t.includes(k));
}

// Only strong DDoS CWEs
function hasStrongDdosCwe(cweIds: string[]): boolean {
  const strong = new Set(['CWE-405','CWE-406','CWE-770']);
  return cweIds?.some(id => strong.has(id));
}

// References: keep ddos terms and classic ddos vendors; avoid "denial of service"
function hasDdosRefHints(refs: string[]): boolean {
  if (!refs?.length) return false;
  const terms = ['ddos','drdos','amplification','reflection','booter','stresser'];
  const vendors = ['cloudflare','akamai','netscout','arbor','imperva','cisa.gov'];
  return refs.some(r => terms.some(t => r.includes(t))) || refs.some(r => vendors.some(v => r.includes(v)));
}

// -------- Your original lightweight helpers (kept) --------

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

function getCweIds(cve: any): string[] {
  const weaknesses = cve?.weaknesses;
  const result: string[] = [];
  if (Array.isArray(weaknesses)) {
    for (const w of weaknesses) {
      const descs = w?.description;
      if (Array.isArray(descs)) {
        for (const d of descs) {
          if (typeof d?.value === 'string' && d.value) result.push(d.value);
        }
      }
    }
  }
  return result;
}

function getReferences(cve: any): string[] {
  const references = cve?.references;
  const result: string[] = [];
  if (Array.isArray(references)) {
    for (const ref of references) {
      if (ref?.url)  result.push(String(ref.url).toLowerCase());
      if (ref?.name) result.push(String(ref.name).toLowerCase());
    }
  }
  return result;
}

// --------------- Final analyzer ---------------

export function getDdosAnalysisDetails(cve: any): DdosAnalysis {
  const reasons: string[] = [];
  let score = 0;

  // CVSS gate
  const norms = extractNormCvss(cve);
  const gate = metricsPassGate(norms);
  if (!gate.passed) {
    return { isDdosRelated: false, reasons: ['CVSS gate failed (need AV: Network/Adjacent, A: High, C/I: Low)'], confidence: 'LOW' };
  }
  score += 1 + gate.bonus;
  reasons.push(...gate.reasons);

  // Description
  const desc = getEnglishDescription(cve);
  if (hasAmplificationLexicon(desc)) { score += 3; reasons.push('Amplification/reflection/spoofing lexicon found'); }
  if (hasNegativeHints(desc))       { score -= 2; reasons.push('Negative indicators for generic/local DoS or non-DDoS web vulns'); }

  // CWE
  const cwes = getCweIds(cve);
  if (hasStrongDdosCwe(cwes)) { score += 2; reasons.push(`Strong DDoS CWE present: ${cwes.join(', ')}`); }

  // References
  const refs = getReferences(cve);
  if (hasDdosRefHints(refs)) { score += 2; reasons.push('References indicate DDoS/amplification'); }

  // NEW hard requirement: at least one DDoS-specific signal
  const hasDdosSignal =
  hasAmplificationLexicon(desc) ||
  hasStrongDdosCwe(cwes) ||
  hasDdosRefHints(refs);


  // Decision based on score thresholds
  let confidence: Confidence = 'LOW';
  if (score >= 6) confidence = 'HIGH';
  else if (score >= 4) confidence = 'MEDIUM';
  
  // Consider DDoS-related if score >= 2 (includes LOW, MEDIUM, HIGH)
  const isDdosRelated = score >= 2;

  return { isDdosRelated, reasons, confidence };
}