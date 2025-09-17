import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';
import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';
import { saveTableEntriesToSqlite } from './saveToSqlite';

const OUTPUT_DIR = path.join(process.cwd(), 'cveJsons');
const SQLITE_DB_PATH = path.join(process.cwd(), 'cve_database.db');

function getYearZipUrl(year: number): string {
  return `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.json.zip`;
}

function getZipAndJsonPaths(year: number): { zipPath: string; jsonPath: string } {
  const zipPath = path.join(OUTPUT_DIR, `nvdcve-2.0-${year}.json.zip`);
  const jsonPath = path.join(OUTPUT_DIR, `nvdcve-2.0-${year}.json`);
  return { zipPath, jsonPath };
}

async function fetchYearEntries(year: number = 2002): Promise<void> {
  try {
    console.log(`Starting download of CVEs for year ${year} from NVD...`);

    if (!fs.existsSync(OUTPUT_DIR)) {
      fs.mkdirSync(OUTPUT_DIR, { recursive: true });
      console.log(`Created directory: ${OUTPUT_DIR}`);
    }

    const url = getYearZipUrl(year);
    const { zipPath, jsonPath } = getZipAndJsonPaths(year);

    console.log(`Downloading from: ${url}`);
    const response = await axios({
      method: 'GET',
      url,
      responseType: 'stream',
      timeout: 120000,
    });

    const writer = fs.createWriteStream(zipPath);
    response.data.pipe(writer);

    await new Promise<void>((resolve, reject) => {
      writer.on('finish', () => resolve());
      writer.on('error', reject);
    });

    console.log(`Downloaded zip file to: ${zipPath}`);

    console.log('Extracting zip file...');
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();

    if (zipEntries.length === 0) {
      throw new Error('No files found in the downloaded zip');
    }

    const jsonEntry = zipEntries.find(entry => entry.entryName.endsWith('.json'));
    if (!jsonEntry) {
      throw new Error('No JSON file found in the downloaded zip');
    }

    const jsonContent = zip.readAsText(jsonEntry);
    fs.writeFileSync(jsonPath, jsonContent, 'utf8');

    console.log(`Extracted JSON file to: ${jsonPath}`);

    const cveData = JSON.parse(jsonContent);
    const cveCount = cveData.vulnerabilities?.length || 0;
    console.log(`Successfully downloaded and extracted ${cveCount} CVEs for year ${year}`);

    fs.unlinkSync(zipPath);
    console.log('Cleaned up temporary zip file');

    console.log('\nProcessing CVEs and extracting table entries...');
    const tableEntries = extractTableEntriesFromDataFeedFile(jsonPath);

    const processedFilePath = path.join(OUTPUT_DIR, `${year}-cves-processed.txt`);
    const ws = fs.createWriteStream(processedFilePath, { encoding: 'utf8' });

    for (const entry of tableEntries) {
      ws.write(JSON.stringify(entry));
      ws.write('\n');
    }
    ws.end();

    await new Promise<void>((resolve, reject) => {
      ws.on('finish', () => {
        console.log(`✅ Processed ${tableEntries.length} table entries`);
        console.log(`📁 Saved processed entries to: ${processedFilePath}`);
        resolve();
      });
      ws.on('error', reject);
    });

    // Insert only into SQLite database (no upsert)
    console.log(`\nInserting ${tableEntries.length} entries into SQLite at: ${SQLITE_DB_PATH}`);
    await saveTableEntriesToSqlite(tableEntries, SQLITE_DB_PATH, {
      createBackup: true,
      batchSize: 1000,
      verbose: true,
      saveMode: 'insertOnly'
    });

    console.log('Download, processing, and database insert completed successfully!');

  } catch (error) {
    console.error('Error fetching year entries:', error);
    throw error;
  }
}

async function main(): Promise<void> {
  try {
    const yearArg = process.argv.find(arg => /^--year=\d{4}$/.test(arg));
    const year = yearArg ? parseInt(yearArg.split('=')[1], 10) : 2002;
    await fetchYearEntries(year);
  } catch (error) {
    console.error('Failed to fetch year entries:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { fetchYearEntries };


