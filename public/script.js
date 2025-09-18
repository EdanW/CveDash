let cves = [];
let showDDoSOnly = false;

// Map frontend metric version values to database values
function mapMetricVersion(frontendValue) {
    const mapping = {
        'latest': '3.1',  // Default to CVSS 3.1
        'v2': '2.0',
        'v3.0': '3.0', 
        'v3.1': '3.1',
        'v4.0': '4.0'
    };
    return mapping[frontendValue] || '3.1';
}

// Load CVEs on page load
document.addEventListener('DOMContentLoaded', () => {
    loadCVEsOnce();
    initSeverityChart();
    initYearlyTrendsChart();
    initMetricToggle();
});

// Load CVEs once on page load from static data
async function loadCVEsOnce() {
    try {
        // For now, use a small sample dataset instead of loading everything
        // This avoids the massive API call and database query
        cves = [
            {
                id: '1',
                cveId: 'CVE-2023-1234',
                title: 'Sample CVE for Testing',
                description: 'This is a sample CVE entry for testing the dashboard.',
                severity: 'HIGH',
                cvssScore: 8.5,
                attackVector: 'NETWORK',
                affectedProducts: ['Sample Product v1.0'],
                publishedDate: '2023-01-15',
                lastModifiedDate: '2023-01-20',
                status: 'ACTIVE',
                ddosRelated: true,
                references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-1234']
            }
        ];
        
        displayCVEs();
        updateStats();
    } catch (error) {
        console.error('Error loading CVEs:', error);
        alert(`Error loading CVE data: ${error.message}`);
    }
}

// Legacy function - now just updates display with current data
async function loadCVEs() {
    displayCVEs();
    updateStats();
}

function displayCVEs() {
    const container = document.getElementById('cvesContainer');
    container.innerHTML = '';
    
    const filteredCVEs = showDDoSOnly ? cves.filter(cve => cve.ddosRelated) : cves;
    
    filteredCVEs.forEach(cve => {
        const card = document.createElement('div');
        card.className = 'cve-card';
        
        const severityClass = `severity-${cve.severity.toLowerCase()}`;
        const statusClass = `status-${cve.status.toLowerCase()}`;
        
        card.innerHTML = `
            <div class="severity-badge ${severityClass}">
                ${cve.severity}
            </div>
            <h3>${cve.cveId} - ${cve.title}</h3>
            <div class="cve-description">${cve.description}</div>
            <div class="cve-info">
                <strong>CVSS Score:</strong> 
                <span class="cvss-score">${cve.cvssScore}</span>
                <span class="status-badge ${statusClass}">${cve.status}</span>
            </div>
            <div class="cve-info"><strong>Attack Vector:</strong> ${cve.attackVector}</div>
            <div class="cve-info"><strong>Published:</strong> ${formatDate(cve.publishedDate)}</div>
            <div class="cve-info"><strong>Last Modified:</strong> ${formatDate(cve.lastModifiedDate)}</div>
            <div class="affected-products">
                <strong>Affected Products:</strong> ${cve.affectedProducts.join(', ')}
            </div>
            <div class="references">
                <strong>References:</strong>
                ${cve.references.map(ref => `<a href="${ref}" target="_blank">${ref}</a>`).join('')}
            </div>
        `;
        container.appendChild(card);
    });
}

async function updateStats() {
    // Show loading state for total CVEs and average CVSS
    document.getElementById('totalCVEs').textContent = '⏳';
    document.getElementById('avgCVSS').textContent = '⏳';
    
    // Update the label with current metric version
    const metricVersion = window.currentMetricVersion || 'latest';
    const mappedVersion = mapMetricVersion(metricVersion);
    const versionDisplay = metricVersion === 'latest' ? 'CVSS 3.1' : `CVSS ${mappedVersion}`;
    document.getElementById('totalCVEsLabel').textContent = `DDoS vs Other CVEs (${versionDisplay})`;
    
    try {
        // Fetch total CVE count from database based on current metric version
        const response = await fetch(`/api/cves/stats/count?metricVersion=${encodeURIComponent(mappedVersion)}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                // Display ratio information with percentage on separate line
                const ratioText = `${data.ddosCount.toLocaleString()} / ${data.nonDdosCount.toLocaleString()}<br>${data.ddosRatio}%`;
                document.getElementById('totalCVEs').innerHTML = ratioText;
                document.getElementById('avgCVSS').textContent = data.averageScore.toFixed(1);
            } else {
                console.error('Failed to get CVE count:', data.error);
                // Fallback to local data
                updateStatsFromLocalData();
            }
        } else {
            console.error('HTTP error getting CVE count:', response.status);
            // Fallback to local data
            updateStatsFromLocalData();
        }
    } catch (error) {
        console.error('Error fetching CVE count:', error);
        // Fallback to local data
        updateStatsFromLocalData();
    }
    
    // Update other stats from local data (these don't depend on metric version)
    const criticalCVEs = cves.filter(c => c.severity === 'CRITICAL').length;
    const activeCVEs = cves.filter(c => c.status === 'ACTIVE').length;
    
    document.getElementById('criticalCVEs').textContent = criticalCVEs;
    document.getElementById('activeCVEs').textContent = activeCVEs;
}

function updateStatsFromLocalData() {
    const totalCVEs = cves.length;
    const avgCVSS = cves.length > 0 ? (cves.reduce((sum, c) => sum + c.cvssScore, 0) / cves.length).toFixed(1) : '0.0';
    
    document.getElementById('totalCVEs').textContent = totalCVEs;
    document.getElementById('avgCVSS').textContent = avgCVSS;
}


async function refreshData() {
    // Refresh both the pie chart, yearly trends chart, and stats with current metric version
    await Promise.all([
        showSeverityDistribution(),
        showYearlyTrends(),
        updateStats()
    ]);
}

function filterDDoSOnly() {
    showDDoSOnly = !showDDoSOnly;
    const button = document.querySelector('.btn-warning');
    if (showDDoSOnly) {
        button.textContent = '🛡️ Show All';
        button.classList.remove('btn-warning');
        button.classList.add('btn-info');
    } else {
        button.textContent = '🛡️ DDoS Only';
        button.classList.remove('btn-info');
        button.classList.add('btn-warning');
    }
    displayCVEs();
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

// Fetch and display severity distribution in a simple popup
async function showSeverityDistribution() {
    // Show loading state
    showChartLoading();
    
    try {
        const metricVersion = window.currentMetricVersion || 'latest';
        const mappedVersion = mapMetricVersion(metricVersion);
        const response = await fetch(`/api/cves/stats/severity?metricVersion=${encodeURIComponent(mappedVersion)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Failed to load severity distribution');
        }
        
        const dist = data.distribution || {};
        console.log('Severity distribution data:', dist);
        console.log('Metric version:', data.metricVersion);
        renderSeverityChart(dist, data.metricVersion);
    } catch (e) {
        console.error('Error fetching severity distribution', e);
        showChartError(`Error loading severity distribution: ${e.message}`);
    }
}

// Initialize and render severity pie chart
let severityChartInstance = null;

function initSeverityChart() {
    // Fetch immediately on load
    showSeverityDistribution();
}

// Show loading state in the chart area
function showChartLoading() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (severityChartInstance) {
        severityChartInstance.destroy();
        severityChartInstance = null;
    }
    
    // Create a simple loading chart
    severityChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Loading...'],
            datasets: [{
                data: [1],
                backgroundColor: ['#6c757d'],
                borderColor: '#222',
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: '🔄 Loading Severity Distribution...',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                }
            },
            layout: { padding: 20 },
            responsive: true,
            animation: {
                duration: 0 // Disable animation for loading state
            }
        }
    });
}

// Show error state in the chart area
function showChartError(message) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (severityChartInstance) {
        severityChartInstance.destroy();
        severityChartInstance = null;
    }
    
    // Create a simple error chart
    severityChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Error'],
            datasets: [{
                data: [1],
                backgroundColor: ['#dc3545'],
                borderColor: '#222',
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: `❌ ${message}`,
                    color: '#dc3545',
                    font: {
                        size: 14
                    }
                }
            },
            layout: { padding: 20 },
            responsive: true,
            animation: {
                duration: 0 // Disable animation for error state
            }
        }
    });
}

function renderSeverityChart(distribution, metricVersion) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    console.log('Rendering severity chart with distribution:', distribution);
    console.log('Labels and data arrays will be built from:', Object.keys(distribution));

    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const labels = [];
    const data = [];

    order.forEach((k) => {
        if (distribution[k] !== undefined) {
            labels.push(k);
            data.push(distribution[k]);
        }
    });

    console.log('Final labels:', labels);
    console.log('Final data:', data);

    // If no data, show a message
    if (labels.length === 0 || data.length === 0) {
        console.log('No data to display in pie chart');
        if (severityChartInstance) {
            severityChartInstance.destroy();
        }
        severityChartInstance = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['No Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#6c757d'],
                    borderColor: '#222',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'No severity data available',
                        color: '#ffffff'
                    }
                },
                layout: { padding: 20 },
                responsive: true
            }
        });
        return;
    }

    const colors = {
        CRITICAL: '#dc3545',
        HIGH: '#fd7e14',
        MEDIUM: '#ffc107',
        LOW: '#28a745',
        UNKNOWN: '#6c757d'
    };

    const backgroundColor = labels.map(l => colors[l] || '#6c757d');

    if (severityChartInstance) {
        severityChartInstance.destroy();
    }

    severityChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor,
                borderColor: '#222',
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff',
                        generateLabels: (chart) => {
                            const dataset = chart.data.datasets[0];
                            return chart.data.labels.map((label, i) => ({
                                text: label.charAt(0) + label.slice(1).toLowerCase(),
                                fillStyle: dataset.backgroundColor[i],
                                strokeStyle: dataset.backgroundColor[i],
                                lineWidth: 1,
                                hidden: !chart.getDataVisibility(i),
                                index: i
                            }));
                        }
                    }
                },
                title: {
                    display: true,
                    text: `Severity Distribution (CVSS ${metricVersion})`,
                    color: '#ffffff'
                }
            },
            layout: { padding: 0 },
            responsive: true
        }
    });
}

// Yearly CVE trends chart functions
let yearlyTrendsChartInstance = null;

// Initialize and render yearly trends chart
function initYearlyTrendsChart() {
    // Fetch immediately on load
    showYearlyTrends();
}

// Fetch and display yearly CVE trends
async function showYearlyTrends() {
    // Show loading state
    showYearlyTrendsLoading();
    
    try {
        const metricVersion = window.currentMetricVersion || 'latest';
        const mappedVersion = mapMetricVersion(metricVersion);
        const response = await fetch(`/api/cves/stats/yearly-trends?metricVersion=${encodeURIComponent(mappedVersion)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        if (!data.success) {
            throw new Error(data.error || 'Failed to load yearly CVE trends');
        }
        
        const yearlyData = data.yearlyData || {};
        renderYearlyTrendsChart(yearlyData, data.metricVersion);
    } catch (e) {
        console.error('Error fetching yearly CVE trends', e);
        showYearlyTrendsError(`Error loading yearly CVE trends: ${e.message}`);
    }
}

// Show loading state in the yearly trends chart area
function showYearlyTrendsLoading() {
    const ctx = document.getElementById('yearlyTrendsChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (yearlyTrendsChartInstance) {
        yearlyTrendsChartInstance.destroy();
        yearlyTrendsChartInstance = null;
    }
    
    // Create a simple loading chart
    yearlyTrendsChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Loading...'],
            datasets: [{
                data: [0],
                borderColor: '#6c757d',
                backgroundColor: 'rgba(108, 117, 125, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: '🔄 Loading Yearly CVE Trends...',
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                }
            },
            layout: { padding: 20 },
            responsive: true,
            animation: {
                duration: 0 // Disable animation for loading state
            }
        }
    });
}

// Show error state in the yearly trends chart area
function showYearlyTrendsError(message) {
    const ctx = document.getElementById('yearlyTrendsChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (yearlyTrendsChartInstance) {
        yearlyTrendsChartInstance.destroy();
        yearlyTrendsChartInstance = null;
    }
    
    // Create a simple error chart
    yearlyTrendsChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Error'],
            datasets: [{
                data: [0],
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: `❌ ${message}`,
                    color: '#dc3545',
                    font: {
                        size: 14
                    }
                }
            },
            layout: { padding: 20 },
            responsive: true,
            animation: {
                duration: 0 // Disable animation for error state
            }
        }
    });
}

function renderYearlyTrendsChart(yearlyData, metricVersion) {
    const ctx = document.getElementById('yearlyTrendsChart');
    if (!ctx) return;

    // Create labels for years 2002-2025
    const labels = [];
    const data = [];
    
    for (let year = 2002; year <= 2025; year++) {
        labels.push(year.toString()); // Format as 2002, 2003, etc.
        data.push(yearlyData[year.toString()] || 0);
    }

    if (yearlyTrendsChartInstance) {
        yearlyTrendsChartInstance.destroy();
    }

    yearlyTrendsChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'CVEs Published',
                data,
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0,
                pointBackgroundColor: '#007bff',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: `CVE Trends by Year (CVSS ${metricVersion}) - All CVEs`,
                    color: '#ffffff',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: false
                    },
                    ticks: {
                        color: '#ffffff',
                        maxTicksLimit: 24, // Show all years from 2002-2025
                        callback: function(value, index) {
                            return labels[index]; // Display the year labels
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    display: false
                }
            },
            layout: { padding: 10 },
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

// Metric version toggle with persistence
function initMetricToggle() {
    const select = document.getElementById('metricVersionSelect');
    if (!select) return;
    
    // Load saved metric version from localStorage
    const savedMetricVersion = localStorage.getItem('metricVersion') || 'latest';
    select.value = savedMetricVersion;
    window.currentMetricVersion = savedMetricVersion;
    
    select.addEventListener('change', (e) => {
        const newValue = e.target.value;
        window.currentMetricVersion = newValue;
        
        // Persist the selection
        localStorage.setItem('metricVersion', newValue);
        
        // Refetch data with new metric version
        refreshData();
    });
}

