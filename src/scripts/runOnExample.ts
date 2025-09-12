import { extractTableEntriesFromJson } from './extractTableEntriesFromJson';

const fs = require('fs');
const path = require('path');

function main() {
  const examplePath = path.resolve(__dirname, '../examples/jsonExample.json');
  const text = fs.readFileSync(examplePath, 'utf8');
  const json = JSON.parse(text);
  const cve = json.cve ?? json;
  const results = extractTableEntriesFromJson(cve);
  console.log(JSON.stringify(results, null, 2));
}

main();
