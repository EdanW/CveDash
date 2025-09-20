// --- Tight DDoS detector (precision-focused) ---

export function detectDdosRelated(cve: any): boolean {
  const details = getDdosAnalysisDetails(cve);
  return details.isDdosRelated && details.confidence !== 'LOW';
}

// Normalize CVSS from v2/v3/v4 into comparable fields
type NormCvss = {
  av?: 'NETWORK'|'ADJACENT'|'LOCAL'|'PHYSICAL';
  ai?: 'NONE'|'LOW'|'HIGH'|'COMPLETE'|'H'|'L'|'N'; // v4 uses H/L/N
  pr?: 'NONE'|'LOW'|'HIGH'|'N'|'L'|'H';
  ui?: 'NONE'|'REQUIRED'|'N'|'R';
  ac?: 'LOW'|'HIGH'|'L'|'H';
};

function extractNormCvss(cve: any): NormCvss[] {
  const m = cve?.metrics || {};
  const all: any[] = [
    ...(m.cvssMetricV40 || []),
    ...(m.cvssMetricV31 || []),
    ...(m.cvssMetricV30 || []),
    ...(m.cvssMetricV2  || []),
  ];
  const out: NormCvss[] = [];
  for (const x of all) {
    const d = x?.cvssData || {};
    const av = (d.attackVector || d.accessVector || '').toUpperCase();
    const ai = (d.availabilityImpact || d.va || d.vi || '').toUpperCase(); // v4: VA
    const pr = (d.privilegesRequired || d.pr || '').toUpperCase();
    const ui = (d.userInteraction || d.ui || '').toUpperCase();
    const ac = (d.attackComplexity || d.accessComplexity || d.ac || '').toUpperCase();
    out.push({ av, ai, pr, ui, ac });
  }
  return out;
}

function metricsPassDdosGate(norms: NormCvss[]): {passed: boolean, bonus: number, reason: string[]} {
  let passed = false;
  let bonus = 0;
  const reasons: string[] = [];
  for (const n of norms) {
    const avOK = n.av === 'NETWORK' || n.av === 'ADJACENT';
    const aiVal = n.ai;
    const aiHigh = aiVal === 'HIGH' || aiVal === 'COMPLETE' || aiVal === 'H';
    if (avOK && aiHigh) {
      passed = true;
      reasons.push(`CVSS gate: AV=${n.av}, A=${aiVal}`);
      if (n.pr === 'NONE' || n.pr === 'N') { bonus += 1; reasons.push('PR:N'); }
      if (n.ui === 'NONE' || n.ui === 'N') { bonus += 1; reasons.push('UI:N'); }
      if (n.ac === 'LOW'  || n.ac === 'L') { bonus += 1; reasons.push('AC:L'); }
      break;
    }
  }
  return { passed, bonus, reason: reasons };
}

// --- Keep your existing helpers (unchanged) ---
function getEnglishDescription(cve: any): string { /* as in your code */ return (function(){
  const descriptions = cve?.descriptions;
  if (Array.isArray(descriptions)) {
    const en = descriptions.find((d: any) => d?.lang === 'en');
    if (en?.value) return String(en.value).toLowerCase();
    const first = descriptions[0]?.value;
    if (first) return String(first).toLowerCase();
  }
  return '';
})(); }

function getCweIds(cve: any): string[] { /* as in your code */ return (function(){
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
})(); }

function getReferences(cve: any): string[] { /* as in your code */ return (function(){
  const references = cve?.references;
  const result: string[] = [];
  if (Array.isArray(references)) {
    for (const ref of references) {
      if (ref?.url)  result.push(String(ref.url).toLowerCase());
      if (ref?.name) result.push(String(ref.name).toLowerCase());
    }
  }
  return result;
})(); }

// --- New, tighter text/indicator checks (no "denial of service") ---

function checkAmplificationLexicon(text: string): boolean {
  if (!text) return false;
  const kws = [
    // mechanics
    'amplification', 'amplify', 'reflect', 'reflection', 'reflected', 'drdos',
    'spoof', 'spoofed', 'spoofing', 'open resolver', 'traffic amplification',
    'bandwidth exhaustion', 'packet amplification', 'attack amplification',
    // well-known DDoS-able protocols/features
    'ntp', 'monlist', 'dns', 'open dns resolver', 'mdns', 'ssdp', 'ws-discovery',
    'cldap', 'ldap', 'snmp', 'chargen', 'qotd', 'mssql', 'memcached', 'coap',
    'ripv1', 'nbns', 'ssdp', 'sntp'
  ];
  return kws.some(k => text.includes(k));
}

function checkNegativeDoSIndicators(text: string): boolean {
  if (!text) return false;
  const negatives = [
    // classic local/impl bugs more likely simple DoS
    'null pointer', 'use-after-free', 'out-of-bounds', 'oob read', 'oob write',
    'integer overflow', 'race condition', 'infinite loop', 'resource exhaustion',
    'memory exhaustion', 'cpu exhaustion', 'hang', 'crash', 'kernel panic',
    'local user', 'local attacker', 'authenticated user', 'privileged user'
  ];
  return negatives.some(k => text.includes(k));
}

function checkDdosCweIdsTight(cweIds: string[]): boolean {
  // Narrow only to strong DDoS signals
  const strong = new Set([
    'CWE-405', // Asymmetric Resource Consumption (Amplification)
    'CWE-406', // Insufficient Control of Network Message Volume (Amplification)
    'CWE-770', // Allocation Without Limits/Throttling
  ]);
  return cweIds.some(id => strong.has(id));
}

function checkReferenceHints(references: string[]): boolean {
  if (!references?.length) return false;
  // Keep "ddos" but drop "denial of service"
  const refKws = ['ddos', 'amplification', 'reflection', 'drdos', 'booter', 'stresser'];
  // Give extra weight if reputable DDoS sources appear
  const ddosDomains = ['cloudflare', 'akamai', 'netscout', 'arbor', 'imperva', 'cisa.gov'];
  return references.some(r => refKws.some(k => r.includes(k))) ||
         references.some(r => ddosDomains.some(d => r.includes(d)));
}

// --- Final explainer with scoring ---
export function getDdosAnalysisDetails(cve: any): {
  isDdosRelated: boolean;
  reasons: string[];
  confidence: 'LOW'|'MEDIUM'|'HIGH';
} {
  const reasons: string[] = [];
  let score = 0;

  // 1) CVSS gate
  const norms = extractNormCvss(cve);
  const gate = metricsPassDdosGate(norms);
  if (!gate.passed) {
    return { isDdosRelated: false, reasons: ['CVSS gate failed (need AV:N/A and A:High)'], confidence: 'LOW' };
  }
  score += 1 + gate.bonus; // base + small bonus from PR/UI/AC
  reasons.push(...gate.reason);

  // 2) Textual heuristics (description) — no "denial of service"
  const desc = getEnglishDescription(cve);
  if (checkAmplificationLexicon(desc)) { score += 3; reasons.push('Amplification/reflection/spoofing lexicon found'); }
  if (checkNegativeDoSIndicators(desc)) { score -= 2; reasons.push('Negative indicators for generic/local DoS'); }

  // 3) CWE (tight)
  const cwes = getCweIds(cve);
  if (checkDdosCweIdsTight(cwes)) { score += 2; reasons.push(`Strong DDoS CWE present: ${cwes.join(', ')}`); }

  // 4) References (keep “ddos”, drop “denial of service”)
  const refs = getReferences(cve);
  if (checkReferenceHints(refs)) { score += 2; reasons.push('References indicate DDoS/amplification'); }

  // Decision thresholds:
  // - High confidence: strong text/ref + CVSS gate ⇒ score ≥ 6
  // - Medium: CVSS gate + at least one strong signal ⇒ score ≥ 4
  let confidence: 'LOW'|'MEDIUM'|'HIGH' = 'LOW';
  if (score >= 6) confidence = 'HIGH';
  else if (score >= 4) confidence = 'MEDIUM';

  return { isDdosRelated: confidence !== 'LOW', reasons, confidence };
}
