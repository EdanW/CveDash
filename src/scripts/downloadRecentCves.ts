import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';
import { extractTableEntriesFromDataFeedFile } from './extractTableEntriesFromJson';

const NVD_RECENT_URL = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip';
const OUTPUT_DIR = path.join(process.cwd(), 'cveJsons');
const ZIP_FILE_PATH = path.join(OUTPUT_DIR, 'nvdcve-2.0-recent.json.zip');
const JSON_FILE_PATH = path.join(OUTPUT_DIR, 'nvdcve-2.0-recent.json');

/**
 * Downloads the recent CVEs zip file from NVD and extracts it to cveJsons directory
 */
async function downloadRecentCves(): Promise<void> {
  try {
    console.log('Starting download of recent CVEs from NVD...');
    
    // Ensure output directory exists
    if (!fs.existsSync(OUTPUT_DIR)) {
      fs.mkdirSync(OUTPUT_DIR, { recursive: true });
      console.log(`Created directory: ${OUTPUT_DIR}`);
    }

    // Download the zip file
    console.log(`Downloading from: ${NVD_RECENT_URL}`);
    const response = await axios({
      method: 'GET',
      url: NVD_RECENT_URL,
      responseType: 'stream',
      timeout: 30000, // 30 second timeout
    });

    // Save zip file
    const writer = fs.createWriteStream(ZIP_FILE_PATH);
    response.data.pipe(writer);

    await new Promise<void>((resolve, reject) => {
      writer.on('finish', () => resolve());
      writer.on('error', reject);
    });

    console.log(`Downloaded zip file to: ${ZIP_FILE_PATH}`);

    // Extract the zip file
    console.log('Extracting zip file...');
    const zip = new AdmZip(ZIP_FILE_PATH);
    const zipEntries = zip.getEntries();
    
    if (zipEntries.length === 0) {
      throw new Error('No files found in the downloaded zip');
    }

    // Extract the JSON file
    const jsonEntry = zipEntries.find(entry => entry.entryName.endsWith('.json'));
    if (!jsonEntry) {
      throw new Error('No JSON file found in the downloaded zip');
    }

    const jsonContent = zip.readAsText(jsonEntry);
    fs.writeFileSync(JSON_FILE_PATH, jsonContent, 'utf8');
    
    console.log(`Extracted JSON file to: ${JSON_FILE_PATH}`);

    // Parse and display basic info about the CVEs
    const cveData = JSON.parse(jsonContent);
    const cveCount = cveData.vulnerabilities?.length || 0;
    console.log(`Successfully downloaded and extracted ${cveCount} recent CVEs`);
    
    if (cveCount > 0) {
      console.log(`Total results available: ${cveData.totalResults || 'Unknown'}`);
      console.log(`Results per page: ${cveData.resultsPerPage || 'Unknown'}`);
      console.log(`Data format: ${cveData.format || 'Unknown'}`);
      console.log(`Timestamp: ${cveData.timestamp || 'Unknown'}`);
    }

    // Clean up zip file (optional)
    fs.unlinkSync(ZIP_FILE_PATH);
    console.log('Cleaned up temporary zip file');

    // Process the downloaded CVEs and extract table entries
    console.log('\nProcessing CVEs and extracting table entries...');
    const tableEntries = extractTableEntriesFromDataFeedFile(JSON_FILE_PATH);
    
    // Save processed entries to a file
    const processedFilePath = path.join(OUTPUT_DIR, 'recent-cves-processed.txt');
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

    console.log('Download and processing completed successfully!');

  } catch (error) {
    console.error('Error downloading recent CVEs:', error);
    throw error;
  }
}

/**
 * Main function to run the download
 */
async function main(): Promise<void> {
  try {
    await downloadRecentCves();
  } catch (error) {
    console.error('Failed to download recent CVEs:', error);
    process.exit(1);
  }
}

// Run if this script is executed directly
if (require.main === module) {
  main();
}

export { downloadRecentCves };
