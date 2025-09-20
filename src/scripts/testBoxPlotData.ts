#!/usr/bin/env ts-node

/**
 * Test script to investigate box plot data and the strange distribution
 * Usage: npx ts-node src/scripts/testBoxPlotData.ts
 */

import * as path from 'path';
import { CveSqliteManager } from './saveToSqlite';

async function analyzeBoxPlotData() {
  console.log('📊 Analyzing CVSS score distributions for box plot...\n');

  const dbPath = path.resolve(process.cwd(), 'cve_database.db');
  const manager = new CveSqliteManager(dbPath);

  try {
    const versions = ['2.0', '3.0', '3.1', '4.0'];
    
    for (const version of versions) {
      console.log(`\n🔍 Analyzing CVSS v${version}:`);
      console.log('=' .repeat(50));
      
      // Get raw scores for this version
      const allScores = await manager.getCvssScoresForBoxplot({
        metricVersion: version,
        statusFilter: 'accepted'
      });
      
      const ddosScores = await manager.getCvssScoresForBoxplot({
        metricVersion: version,
        isDdosRelated: true,
        statusFilter: 'accepted'
      });
      
      console.log(`📈 All CVEs: ${allScores.length} entries`);
      console.log(`🎯 DDoS CVEs: ${ddosScores.length} entries`);
      
      if (allScores.length === 0) {
        console.log('❌ No data found for this version');
        continue;
      }
      
      // Analyze the distribution that seems weird
      const scoresForAnalysis = allScores; // You can change this to ddosScores to analyze DDoS only
      
      // Calculate statistics
      const sortedScores = scoresForAnalysis.sort((a, b) => a - b);
      const n = sortedScores.length;
      
      if (n === 0) continue;
      
      const min = sortedScores[0];
      const max = sortedScores[n - 1];
      const mean = sortedScores.reduce((sum, score) => sum + score, 0) / n;
      
      const q1Index = Math.floor(n * 0.25);
      const medianIndex = Math.floor(n * 0.5);
      const q3Index = Math.floor(n * 0.75);
      
      const q1 = sortedScores[q1Index];
      const median = sortedScores[medianIndex];
      const q3 = sortedScores[q3Index];
      
      // Count outliers
      const iqr = q3 - q1;
      const lowerFence = q1 - 1.5 * iqr;
      const upperFence = q3 + 1.5 * iqr;
      const outliers = sortedScores.filter(score => score < lowerFence || score > upperFence);
      
      console.log(`📊 Statistics:`);
      console.log(`   Min: ${min}`);
      console.log(`   Q1: ${q1}`);
      console.log(`   Median: ${median}`);
      console.log(`   Q3: ${q3}`);
      console.log(`   Max: ${max}`);
      console.log(`   Mean: ${mean.toFixed(2)}`);
      console.log(`   Outliers: ${outliers.length}`);
      
      // Check for the weird pattern (Q1 = Median = Q3)
      if (q1 === median && median === q3) {
        console.log(`⚠️  UNUSUAL: Q1 = Median = Q3 = ${q1}`);
        console.log(`   This means most scores are exactly ${q1}`);
        
        // Count how many scores are exactly this value
        const exactMatches = sortedScores.filter(score => score === q1).length;
        const percentage = (exactMatches / n * 100).toFixed(1);
        console.log(`   Exact matches: ${exactMatches} out of ${n} (${percentage}%)`);
        
        // Show the unique scores and their counts
        const scoreFreq: Record<number, number> = {};
        sortedScores.forEach(score => {
          scoreFreq[score] = (scoreFreq[score] || 0) + 1;
        });
        
        console.log(`   📋 Score frequency (top 10):`);
        Object.entries(scoreFreq)
          .sort(([,a], [,b]) => b - a)
          .slice(0, 10)
          .forEach(([score, count]) => {
            const pct = (count / n * 100).toFixed(1);
            console.log(`     ${score}: ${count} times (${pct}%)`);
          });
      }
      
      // Show some sample CVEs for this version
      const sampleCves = await manager.queryEntries({
        metricVersion: version,
        limit: 5,
        statusFilter: 'accepted'
      });
      
      if (sampleCves.length > 0) {
        console.log(`\n📋 Sample CVEs for CVSS v${version}:`);
        sampleCves.forEach((cve, index) => {
          console.log(`   ${index + 1}. ${cve.id} - Score: ${cve.baseScore} (DDoS: ${cve.isDdosRelated ? 'Yes' : 'No'})`);
        });
      }
    }
    
  } catch (error) {
    console.error('❌ Analysis failed:', error);
    process.exit(1);
  } finally {
    await manager.close();
  }
}

// Run the analysis
if (require.main === module) {
  analyzeBoxPlotData().catch(console.error);
}
