let cves = [];
let allDDoSCVEs = [];
let displayedCount = 3;
// Removed showDDoSOnly - now using certainty-based filtering
let selectedYear = 'all';
let selectedMinScore = '0';
let selectedSeverityLevels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
let selectedStatusFilter = 'accepted';
let selectedDdosCertainty = 'all';

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
    initMetricToggle(); // Initialize metric version first
    initStatusFilter(); // Initialize status filter
    initDdosCertaintyFilter(); // Initialize DDoS certainty filter
    initYearFilter(); // Initialize year filter
    initSeverityFilter(); // Initialize severity score filter
    initSeverityLevelFilter(); // Initialize severity level filter
    loadCVEsOnce();
    initSeverityChart();
    initYearlyTrendsChart();
    initCvssDistributionChart();
    initCvssBoxplotChart();
    initCWEWidget();
});

// Load CVEs once on page load from database
async function loadCVEsOnce() {
    // Ensure metric version is initialized before loading CVEs
    if (!window.currentMetricVersion) {
        window.currentMetricVersion = localStorage.getItem('metricVersion') || 'latest';
    }
    await loadDDoSCVEs();
}

// Load DDoS CVEs with current metric version
async function loadDDoSCVEs() {
    try {
        const metricVersion = window.currentMetricVersion || 'latest';
        const mappedVersion = mapMetricVersion(metricVersion);
        
        // Fetch up to 90 DDoS-related CVEs from the database with current metric version and filters
        const yearParam = selectedYear !== 'all' ? `&year=${encodeURIComponent(selectedYear)}` : '';
        const scoreParam = selectedMinScore !== '0' ? `&minScore=${encodeURIComponent(selectedMinScore)}` : '';
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        const ddosCertaintyParam = selectedDdosCertainty !== 'all' ? `&ddosCertainty=${encodeURIComponent(selectedDdosCertainty)}` : '';
        const response = await fetch(`/api/cves/sample/ddos?limit=90&metricVersion=${encodeURIComponent(mappedVersion)}${yearParam}${scoreParam}${statusParam}${ddosCertaintyParam}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                allDDoSCVEs = data.cves;
                displayedCount = 3; // Reset to show 3 initially
                cves = allDDoSCVEs.slice(0, displayedCount);
            } else {
                console.error('Failed to load DDoS CVEs:', data.error);
                // Fallback to sample data if API fails
                allDDoSCVEs = getFallbackCVEs();
                cves = allDDoSCVEs;
            }
        } else {
            console.error('HTTP error loading DDoS CVEs:', response.status);
            // Fallback to sample data if API fails
            allDDoSCVEs = getFallbackCVEs();
            cves = allDDoSCVEs;
        }
        
        // Always call displayCVEs after data is loaded to show the button
        setTimeout(() => {
            displayCVEs();
            updateStats();
        }, 100);
    } catch (error) {
        console.error('Error loading CVEs:', error);
        // Fallback to sample data if everything fails
        allDDoSCVEs = getFallbackCVEs();
        cves = allDDoSCVEs;
        displayCVEs();
        updateStats();
    }
}

// Get fallback CVE data
function getFallbackCVEs() {
    return [
        {
            id: '1',
            cveId: 'CVE-2023-1234',
            title: 'Sample DDoS CVE for Testing',
            description: 'This is a sample DDoS-related CVE entry for testing the dashboard.',
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
}

// Legacy function - now just updates display with current data
async function loadCVEs() {
    displayCVEs();
    updateStats();
}

function displayCVEs() {
    const container = document.getElementById('cvesContainer');
    container.innerHTML = '';
    
    let filteredCVEs = cves; // All CVEs are now DDoS-related, filtered by certainty level
    
    // Apply severity level filter
    filteredCVEs = filteredCVEs.filter(cve => selectedSeverityLevels.includes(cve.severity));
    
    filteredCVEs.forEach(cve => {
        const card = document.createElement('div');
        card.className = 'cve-card';
        
        const severityClass = `severity-${cve.severity.toLowerCase()}`;
        const statusClass = `status-${cve.status.toLowerCase()}`;
        
        card.innerHTML = `
            <div class="severity-badge ${severityClass}">
                ${cve.severity}
            </div>
            <h3>${cve.cveId}</h3>
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
                <strong>Affected Products:</strong> ${cve.affectedProducts.length > 0 ? cve.affectedProducts.join(', ') : 'Not specified'}
            </div>
            <div class="references">
                <strong>References:</strong>
                ${cve.references.map(ref => `<a href="${ref}" target="_blank">View Details</a>`).join('')}
            </div>
        `;
        container.appendChild(card);
    });
    
    // Add "Show More" button if there are more CVEs to display
    const allFilteredCVEs = allDDoSCVEs.filter(cve => selectedSeverityLevels.includes(cve.severity));
    
    console.log('Debug - allFilteredCVEs.length:', allFilteredCVEs.length, 'displayedCount:', displayedCount);
    if (allFilteredCVEs.length > displayedCount) {
        console.log('Adding Show More button');
        const showMoreBtn = document.createElement('div');
        showMoreBtn.className = 'show-more-container';
        showMoreBtn.innerHTML = `
            <button class="btn btn-primary show-more-btn" onclick="showMoreCVEs()">
                📄 Show More
            </button>
        `;
        container.appendChild(showMoreBtn);
    } else {
        console.log('Not adding Show More button - no more CVEs to show');
    }
}

// Show more CVEs function
function showMoreCVEs() {
    const increment = 3; // Show 3 more at a time
    
    // Get all filtered CVEs based on current filters
    const allFilteredCVEs = allDDoSCVEs.filter(cve => selectedSeverityLevels.includes(cve.severity));
    
    displayedCount = Math.min(displayedCount + increment, allFilteredCVEs.length);
    cves = allFilteredCVEs.slice(0, displayedCount);
    displayCVEs();
}

async function updateStats() {
    // Show loading state for DDoS percentage
    document.getElementById('totalCVEs').textContent = '⏳';
    
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
                // Display only percentage
                document.getElementById('totalCVEs').textContent = `${data.ddosRatio}%`;
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
}

function updateStatsFromLocalData() {
    // Calculate DDoS percentage from local data
    const totalCVEs = cves.length;
    const ddosCVEs = cves.filter(c => c.ddosRelated).length;
    const ddosPercentage = totalCVEs > 0 ? ((ddosCVEs / totalCVEs) * 100).toFixed(1) : '0.0';
    
    document.getElementById('totalCVEs').textContent = `${ddosPercentage}%`;
}


async function refreshData() {
    // Refresh the pie chart, yearly trends chart, CVSS distribution chart, box plot, stats, DDoS CVEs, and CWE widget with current metric version
    await Promise.all([
        showSeverityDistribution(),
        showYearlyTrends(),
        showCvssDistribution(),
        showCvssBoxplot(),
        updateStats(),
        loadDDoSCVEs(),
        initCWEWidget()
    ]);
}

// filterDDoSOnly function removed - now using certainty-based filtering

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
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        const ddosCertaintyParam = selectedDdosCertainty !== 'all' ? `&ddosCertainty=${encodeURIComponent(selectedDdosCertainty)}` : '';
        const response = await fetch(`/api/cves/stats/severity?metricVersion=${encodeURIComponent(mappedVersion)}${statusParam}${ddosCertaintyParam}`);
        
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
                    color: '#000000',
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

    // If no data or all data is zero, show a message
    const totalData = data.reduce((sum, value) => sum + value, 0);
    if (labels.length === 0 || data.length === 0 || totalData === 0) {
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
                    color: '#000000'
                }
            },
            layout: { padding: 20 },
            responsive: true,
            maintainAspectRatio: false
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
                        color: '#000000',
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
                    color: '#000000'
                }
            },
            layout: { padding: 0 },
            responsive: true,
            maintainAspectRatio: false
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
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        const ddosCertaintyParam = selectedDdosCertainty !== 'all' ? `&ddosCertainty=${encodeURIComponent(selectedDdosCertainty)}` : '';
        
        // Fetch both all CVEs and DDoS-related CVEs data in parallel
        const [allCvesResponse, ddosCvesResponse] = await Promise.all([
            fetch(`/api/cves/stats/yearly-trends?metricVersion=${encodeURIComponent(mappedVersion)}${statusParam}${ddosCertaintyParam}`),
            fetch(`/api/cves/stats/yearly-ddos-trends?metricVersion=${encodeURIComponent(mappedVersion)}${statusParam}${ddosCertaintyParam}`)
        ]);
        
        if (!allCvesResponse.ok) {
            throw new Error(`HTTP ${allCvesResponse.status}: ${allCvesResponse.statusText}`);
        }
        
        if (!ddosCvesResponse.ok) {
            throw new Error(`HTTP ${ddosCvesResponse.status}: ${ddosCvesResponse.statusText}`);
        }
        
        const allCvesData = await allCvesResponse.json();
        const ddosCvesData = await ddosCvesResponse.json();
        
        if (!allCvesData.success) {
            throw new Error(allCvesData.error || 'Failed to load yearly CVE trends');
        }
        
        if (!ddosCvesData.success) {
            throw new Error(ddosCvesData.error || 'Failed to load yearly DDoS trends');
        }
        
        const yearlyData = allCvesData.yearlyData || {};
        const yearlyDdosData = ddosCvesData.yearlyDdosData || {};
        renderYearlyTrendsChart(yearlyData, yearlyDdosData, allCvesData.metricVersion);
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

function renderYearlyTrendsChart(yearlyData, yearlyDdosData, metricVersion) {
    const ctx = document.getElementById('yearlyTrendsChart');
    if (!ctx) return;

    // Create labels for years 1998-2025
    const labels = [];
    const allCvesData = [];
    const ddosCvesData = [];
    
    for (let year = 1998; year <= 2025; year++) {
        labels.push(year.toString()); // Format as 1998, 1999, etc.
        allCvesData.push(yearlyData[year.toString()] || 0);
        ddosCvesData.push(yearlyDdosData[year.toString()] || 0);
    }

    if (yearlyTrendsChartInstance) {
        yearlyTrendsChartInstance.destroy();
    }

    yearlyTrendsChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'All CVEs',
                    data: allCvesData,
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    borderWidth: 3,
                    fill: false,
                    tension: 0,
                    pointBackgroundColor: '#007bff',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'DDoS Related CVEs',
                    data: ddosCvesData,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    borderWidth: 3,
                    fill: false,
                    tension: 0,
                    pointBackgroundColor: '#dc3545',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }
            ]
        },
        options: {
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        color: '#000000',
                        usePointStyle: true,
                        padding: 20,
                        font: {
                            size: 14
                        }
                    }
                },
                title: {
                    display: true,
                    text: `CVE Trends by Year (CVSS ${metricVersion})`,
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
                        maxTicksLimit: 28, // Show all years from 1998-2025
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

// CVSS Score Distribution chart functions
let cvssDistributionChartInstance = null;

// Initialize and render CVSS distribution chart
function initCvssDistributionChart() {
    // Add toggle event listener
    const cvssToggle = document.getElementById('cvssShowAllToggle');
    if (cvssToggle) {
        cvssToggle.addEventListener('change', showCvssDistribution);
    }
    
    // Fetch immediately on load
    showCvssDistribution();
}

// Fetch and display CVSS score distribution
async function showCvssDistribution() {
    // Show loading state
    showCvssDistributionLoading();
    
    try {
        const metricVersion = window.currentMetricVersion || 'latest';
        const mappedVersion = mapMetricVersion(metricVersion);
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        
        // Check if we should show all CVEs or filter by DDoS certainty
        const cvssToggle = document.getElementById('cvssShowAllToggle');
        const showAll = cvssToggle ? cvssToggle.checked : true;
        const ddosCertaintyParam = showAll ? '' : (selectedDdosCertainty !== 'all' ? `&ddosCertainty=${encodeURIComponent(selectedDdosCertainty)}` : '&ddosCertainty=LOW');
        
        const response = await fetch(`/api/cves/stats/cvss-distribution?metricVersion=${encodeURIComponent(mappedVersion)}${statusParam}${ddosCertaintyParam}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                renderCvssDistributionChart(data.scoreDistribution, data.stats, mappedVersion, !showAll);
                updateCvssStats(data.stats);
            } else {
                showCvssDistributionError(data.error || 'Failed to load CVSS distribution data');
            }
        } else {
            showCvssDistributionError(`HTTP ${response.status}: Failed to load CVSS distribution`);
        }
    } catch (error) {
        console.error('Error loading CVSS distribution:', error);
        showCvssDistributionError('Network error loading CVSS distribution');
    }
}

// Show loading state in the CVSS distribution chart area
function showCvssDistributionLoading() {
    const ctx = document.getElementById('cvssDistributionChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (cvssDistributionChartInstance) {
        cvssDistributionChartInstance.destroy();
        cvssDistributionChartInstance = null;
    }
    
    // Create a simple loading chart
    cvssDistributionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Loading...'],
            datasets: [{
                data: [1],
                backgroundColor: 'rgba(108, 117, 125, 0.3)',
                borderColor: '#6c757d',
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
                    text: '🔄 Loading CVSS Score Distribution...',
                    color: '#ffffff',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                }
            },
            scales: {
                x: { display: false },
                y: { display: false }
            },
            maintainAspectRatio: false
        }
    });
}

// Show error state in the CVSS distribution chart area
function showCvssDistributionError(message) {
    const ctx = document.getElementById('cvssDistributionChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (cvssDistributionChartInstance) {
        cvssDistributionChartInstance.destroy();
        cvssDistributionChartInstance = null;
    }
    
    // Create a simple error chart
    cvssDistributionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Error'],
            datasets: [{
                data: [1],
                backgroundColor: 'rgba(220, 53, 69, 0.3)',
                borderColor: '#dc3545',
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
                        size: 16,
                        weight: 'bold'
                    }
                }
            },
            scales: {
                x: { display: false },
                y: { display: false }
            },
            maintainAspectRatio: false
        }
    });
}

function renderCvssDistributionChart(scoreDistribution, stats, metricVersion, isDdosOnly) {
    const ctx = document.getElementById('cvssDistributionChart');
    if (!ctx) return;

    // Create labels and data arrays
    const labels = scoreDistribution.map(item => item.range);
    const counts = scoreDistribution.map(item => item.count);
    
    // Create colors based on CVSS score ranges (similar to severity colors)
    const backgroundColors = scoreDistribution.map(item => {
        const minScore = item.minScore;
        if (minScore >= 9) return 'rgba(220, 53, 69, 0.8)'; // Critical (Red)
        if (minScore >= 7) return 'rgba(255, 193, 7, 0.8)'; // High (Orange/Yellow)
        if (minScore >= 4) return 'rgba(255, 165, 0, 0.8)'; // Medium (Orange)
        if (minScore >= 0.1) return 'rgba(40, 167, 69, 0.8)'; // Low (Green)
        return 'rgba(108, 117, 125, 0.8)'; // None/Unknown (Gray)
    });
    
    const borderColors = scoreDistribution.map(item => {
        const minScore = item.minScore;
        if (minScore >= 9) return 'rgba(220, 53, 69, 1)';
        if (minScore >= 7) return 'rgba(255, 193, 7, 1)';
        if (minScore >= 4) return 'rgba(255, 165, 0, 1)';
        if (minScore >= 0.1) return 'rgba(40, 167, 69, 1)';
        return 'rgba(108, 117, 125, 1)';
    });

    if (cvssDistributionChartInstance) {
        cvssDistributionChartInstance.destroy();
    }

    cvssDistributionChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: isDdosOnly ? 'DDoS-related CVEs' : 'All CVEs',
                data: counts,
                backgroundColor: backgroundColors,
                borderColor: borderColors,
                borderWidth: 1,
                borderRadius: 4,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        color: '#ffffff',
                        font: {
                            size: 12,
                            weight: 'bold'
                        },
                        padding: 20
                    }
                },
                title: {
                    display: true,
                    text: `CVSS Score Distribution (${metricVersion.toUpperCase()}) - ${isDdosOnly ? 'DDoS-related CVEs' : 'All CVEs'}`,
                    color: '#ffffff',
                    font: {
                        size: 14,
                        weight: 'bold'
                    },
                    padding: {
                        top: 10,
                        bottom: 20
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#ffffff',
                    borderColor: '#ffffff',
                    borderWidth: 1,
                    callbacks: {
                        title: function(tooltipItems) {
                            const item = tooltipItems[0];
                            return `CVSS Score Range: ${item.label}`;
                        },
                        label: function(context) {
                            const count = context.parsed.y;
                            const total = counts.reduce((sum, val) => sum + val, 0);
                            const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
                            return `${context.dataset.label}: ${count} CVEs (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'CVSS Score Range',
                        color: '#ffffff',
                        font: {
                            size: 12,
                            weight: 'bold'
                        }
                    },
                    ticks: {
                        color: '#ffffff',
                        font: {
                            size: 10
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Number of CVEs',
                        color: '#ffffff',
                        font: {
                            size: 12,
                            weight: 'bold'
                        }
                    },
                    ticks: {
                        color: '#ffffff',
                        font: {
                            size: 10
                        },
                        beginAtZero: true
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            layout: { 
                padding: 10 
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

// Update CVSS statistics display
function updateCvssStats(stats) {
    const totalElement = document.getElementById('cvssStatTotal');
    const averageElement = document.getElementById('cvssStatAverage');
    const medianElement = document.getElementById('cvssStatMedian');
    const rangeElement = document.getElementById('cvssStatRange');
    
    if (totalElement) totalElement.textContent = stats.totalEntries.toLocaleString();
    if (averageElement) averageElement.textContent = stats.averageScore.toFixed(1);
    if (medianElement) medianElement.textContent = stats.medianScore.toFixed(1);
    if (rangeElement) rangeElement.textContent = `${stats.minScore.toFixed(1)} - ${stats.maxScore.toFixed(1)}`;
}

// CVSS Box Plot chart functions
let cvssBoxplotChartInstance = null;

// Initialize and render CVSS box plot chart
function initCvssBoxplotChart() {
    // Add toggle event listener
    const cvssBoxplotToggle = document.getElementById('cvssBoxplotDdosToggle');
    if (cvssBoxplotToggle) {
        cvssBoxplotToggle.addEventListener('change', showCvssBoxplot);
    }
    
    // Fetch immediately on load
    showCvssBoxplot();
}

// Fetch and display CVSS box plot data
async function showCvssBoxplot() {
    // Show loading state
    showCvssBoxplotLoading();
    
    try {
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        
        // Check if we should show DDoS only or all CVEs
        const cvssBoxplotToggle = document.getElementById('cvssBoxplotDdosToggle');
        const ddosOnly = cvssBoxplotToggle ? cvssBoxplotToggle.checked : false;
        const ddosCertaintyParam = ddosOnly ? (selectedDdosCertainty !== 'all' ? `&ddosCertainty=${encodeURIComponent(selectedDdosCertainty)}` : '&ddosCertainty=LOW') : '';
        
        const response = await fetch(`/api/cves/stats/cvss-boxplot?${statusParam}${ddosCertaintyParam}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                renderCvssBoxplotChart(data.boxplotData, ddosOnly);
            } else {
                showCvssBoxplotError(data.error || 'Failed to load CVSS box plot data');
            }
        } else {
            showCvssBoxplotError(`HTTP ${response.status}: Failed to load CVSS box plot`);
        }
    } catch (error) {
        console.error('Error loading CVSS box plot:', error);
        showCvssBoxplotError('Network error loading CVSS box plot');
    }
}

// Show loading state in the CVSS box plot chart area
function showCvssBoxplotLoading() {
    const ctx = document.getElementById('cvssBoxplotChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (cvssBoxplotChartInstance) {
        cvssBoxplotChartInstance.destroy();
        cvssBoxplotChartInstance = null;
    }
    
    // Create a simple loading chart
    cvssBoxplotChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Loading...'],
            datasets: [{
                data: [1],
                backgroundColor: 'rgba(108, 117, 125, 0.3)',
                borderColor: '#6c757d',
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: 'Loading CVSS box plot data...',
                    color: '#000000'
                }
            },
            scales: {
                y: { display: false },
                x: { display: false }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

// Show error state in the CVSS box plot chart area
function showCvssBoxplotError(message) {
    const ctx = document.getElementById('cvssBoxplotChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (cvssBoxplotChartInstance) {
        cvssBoxplotChartInstance.destroy();
        cvssBoxplotChartInstance = null;
    }
    
    // Create a simple error chart
    cvssBoxplotChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Error'],
            datasets: [{
                data: [1],
                backgroundColor: 'rgba(220, 53, 69, 0.3)',
                borderColor: '#dc3545',
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: message || 'Error loading CVSS box plot',
                    color: '#dc3545'
                }
            },
            scales: {
                y: { display: false },
                x: { display: false }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function renderCvssBoxplotChart(boxplotData, ddosOnly) {
    const ctx = document.getElementById('cvssBoxplotChart');
    if (!ctx) return;

    // Prepare data for proper box plot
    const versions = ['2.0', '3.0', '3.1', '4.0'];
    const colors = {
        '2.0': '#ff6384',
        '3.0': '#36a2eb', 
        '3.1': '#4bc0c0',
        '4.0': '#9966ff'
    };
    
    const labels = [];
    const datasets = [];
    const backgroundColors = [];
    
    // Check if we have any data
    const hasData = versions.some(version => boxplotData[version] && boxplotData[version].length > 0);
    
    if (!hasData) {
        // Show no data message
        if (cvssBoxplotChartInstance) {
            cvssBoxplotChartInstance.destroy();
        }
        cvssBoxplotChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['No Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: 'rgba(108, 117, 125, 0.3)',
                    borderColor: '#6c757d',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    legend: { display: false },
                    title: {
                        display: true,
                        text: `No CVSS data available${ddosOnly ? ' for DDoS CVEs' : ''}`,
                        color: '#000000'
                    }
                },
                scales: {
                    y: { display: false },
                    x: { display: false }
                },
                responsive: true,
                maintainAspectRatio: false
            }
        });
        return;
    }

    // Build box plot datasets
    versions.forEach(version => {
        if (boxplotData[version] && boxplotData[version].length > 0) {
            const scores = boxplotData[version];
            labels.push(`CVSS v${version}\n(${scores.length} CVEs)`);
            backgroundColors.push(colors[version]);
        }
    });

    // Create datasets for the box plot
    const boxplotDatasets = [];
    versions.forEach((version, index) => {
        if (boxplotData[version] && boxplotData[version].length > 0) {
            boxplotDatasets.push(boxplotData[version]);
        }
    });

    if (cvssBoxplotChartInstance) {
        cvssBoxplotChartInstance.destroy();
    }

    cvssBoxplotChartInstance = new Chart(ctx, {
        type: 'boxplot',
        data: {
            labels: labels,
            datasets: [{
                label: 'CVSS Scores',
                data: boxplotDatasets,
                backgroundColor: backgroundColors.map(color => color + '60'),
                borderColor: backgroundColors,
                borderWidth: 2,
                outlierColor: '#999999',
                outlierRadius: 3,
                itemRadius: 0,
                itemBackgroundColor: 'rgba(0,0,0,0.1)',
                meanBackgroundColor: '#ff0000',
                meanBorderColor: '#ff0000',
                meanRadius: 3
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false // Box plots don't need a legend
                },
                title: {
                    display: true,
                    text: `CVSS Score Distribution by Metric Version${ddosOnly ? ' (DDoS Only)' : ' (All CVEs)'}`,
                    color: '#000000'
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return labels[context[0].dataIndex];
                        },
                        label: function(context) {
                            const stats = context.parsed;
                            return [
                                `Min: ${stats.min.toFixed(1)}`,
                                `Q1: ${stats.q1.toFixed(1)}`,
                                `Median: ${stats.median.toFixed(1)}`,
                                `Q3: ${stats.q3.toFixed(1)}`,
                                `Max: ${stats.max.toFixed(1)}`,
                                `Mean: ${stats.mean ? stats.mean.toFixed(1) : 'N/A'}`,
                                `Outliers: ${stats.outliers ? stats.outliers.length : 0}`
                            ];
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'CVSS Metric Version'
                    }
                },
                y: {
                    beginAtZero: true,
                    max: 10,
                    title: {
                        display: true,
                        text: 'CVSS Score'
                    },
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });
}

// CVE Search functionality
async function searchCVE() {
    const searchInput = document.getElementById('cveSearchInput');
    const searchResultsWidget = document.getElementById('searchResultsWidget');
    const searchResultsContent = document.getElementById('searchResultsContent');
    
    const cveId = searchInput.value.trim();
    
    if (!cveId) {
        alert('Please enter a CVE ID to search for');
        return;
    }
    
    // Show loading state
    searchResultsContent.innerHTML = '<div class="loading">🔍 Searching for CVE...</div>';
    
    try {
        const response = await fetch(`/api/cves/search/${encodeURIComponent(cveId)}`);
        const data = await response.json();
        
        if (data.success) {
            const cve = data.cve;
            displaySearchResult(cve);
        } else {
            searchResultsContent.innerHTML = `
                <div class="search-result">
                    <h4>❌ CVE Not Found</h4>
                    <p>${data.error || 'CVE not found in database'}</p>
                    <p><strong>Tip:</strong> Make sure you entered the correct CVE ID format (e.g., 2009-0041)</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error searching for CVE:', error);
        searchResultsContent.innerHTML = `
            <div class="search-result">
                <h4>❌ Search Error</h4>
                <p>Failed to search for CVE. Please try again.</p>
            </div>
        `;
    }
}

function displaySearchResult(cve) {
    const searchResultsContent = document.getElementById('searchResultsContent');
    
    // All CVEs are now shown - filtering is handled by certainty level
    
    const severityClass = `severity-${cve.severity.toLowerCase()}`;
    const statusClass = `status-${cve.status.toLowerCase()}`;
    
    searchResultsContent.innerHTML = `
        <div class="search-result">
            <h4>${cve.cveId} - ${cve.title}</h4>
            <div class="cve-description">${cve.description}</div>
            <div class="cve-info">
                <strong>Severity:</strong> 
                <span class="severity-badge ${severityClass}">${cve.severity}</span>
                <strong>CVSS Score:</strong> 
                <span class="cvss-score">${cve.cvssScore}</span>
            </div>
            <div class="cve-info">
                <strong>Status:</strong> 
                <span class="status-badge ${statusClass}">${cve.status}</span>
                <strong>DDoS Related:</strong> 
                <span style="color: ${cve.ddosRelated ? '#28a745' : '#dc3545'}; font-weight: bold;">
                    ${cve.ddosRelated ? 'Yes' : 'No'}
                </span>
            </div>
            <div class="cve-info"><strong>Attack Vector:</strong> ${cve.attackVector}</div>
            <div class="cve-info"><strong>Published:</strong> ${formatDate(cve.publishedDate)}</div>
            <div class="cve-info"><strong>Last Modified:</strong> ${formatDate(cve.lastModifiedDate)}</div>
            <div class="cve-info"><strong>Metric Version:</strong> CVSS ${cve.metricVersion}</div>
            <div class="references">
                <strong>References:</strong>
                ${cve.references.map(ref => `<a href="${ref}" target="_blank">${ref}</a>`).join('')}
            </div>
        </div>
    `;
}

// Clear search results and show placeholder
function clearSearchResults() {
    const searchResultsContent = document.getElementById('searchResultsContent');
    searchResultsContent.innerHTML = `
        <div class="search-placeholder">
            <p>🔍 Look for a CVE</p>
        </div>
    `;
}

// Allow Enter key to trigger search and clear results when input is empty
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('cveSearchInput');
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchCVE();
            }
        });
        
        // Clear search results when input is empty
        searchInput.addEventListener('input', function(e) {
            if (e.target.value.trim() === '') {
                clearSearchResults();
            }
        });
    }
});

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

// Status filter toggle with persistence
function initStatusFilter() {
    const select = document.getElementById('statusFilterSelect');
    if (!select) return;
    
    // Load saved status filter from localStorage
    const savedStatusFilter = localStorage.getItem('statusFilter') || 'accepted';
    select.value = savedStatusFilter;
    selectedStatusFilter = savedStatusFilter;
    
    select.addEventListener('change', (e) => {
        const newValue = e.target.value;
        selectedStatusFilter = newValue;
        
        // Persist the selection
        localStorage.setItem('statusFilter', newValue);
        
        // Refetch data with new status filter
        refreshData();
    });
}

// DDoS Certainty filter initialization
function initDdosCertaintyFilter() {
    const select = document.getElementById('ddosCertaintySelect');
    if (!select) return;
    
    // Load saved DDoS certainty from localStorage
    const savedDdosCertainty = localStorage.getItem('selectedDdosCertainty') || 'all';
    select.value = savedDdosCertainty;
    selectedDdosCertainty = savedDdosCertainty;
    
    select.addEventListener('change', (e) => {
        const newValue = e.target.value;
        selectedDdosCertainty = newValue;
        
        // Persist the selection
        localStorage.setItem('selectedDdosCertainty', newValue);
        
        // Refetch data with new DDoS certainty filter
        refreshData();
    });
}

// Year filter initialization
function initYearFilter() {
    const select = document.getElementById('yearFilter');
    if (!select) return;
    
    // Load saved year from localStorage
    const savedYear = localStorage.getItem('selectedYear') || 'all';
    select.value = savedYear;
    selectedYear = savedYear;
    
    select.addEventListener('change', (e) => {
        const newValue = e.target.value;
        selectedYear = newValue;
        
        // Persist the selection
        localStorage.setItem('selectedYear', newValue);
        
        // Refetch data with new year filter
        refreshData();
    });
}

// Severity score filter initialization
function initSeverityFilter() {
    const select = document.getElementById('severityFilter');
    if (!select) return;
    
    // Load saved min score from localStorage
    const savedMinScore = localStorage.getItem('selectedMinScore') || '0';
    select.value = savedMinScore;
    selectedMinScore = savedMinScore;
    
    select.addEventListener('change', (e) => {
        const newValue = e.target.value;
        selectedMinScore = newValue;
        
        // Persist the selection
        localStorage.setItem('selectedMinScore', newValue);
        
        // Refetch data with new severity filter
        refreshData();
    });
}

// Severity level filter initialization
function initSeverityLevelFilter() {
    const checkboxes = document.querySelectorAll('.severity-checkbox input[type="checkbox"]');
    if (!checkboxes.length) return;
    
    // Load saved severity levels from localStorage
    const savedSeverityLevels = localStorage.getItem('selectedSeverityLevels');
    if (savedSeverityLevels) {
        selectedSeverityLevels = JSON.parse(savedSeverityLevels);
    }
    
    // Set initial checkbox states
    checkboxes.forEach(checkbox => {
        checkbox.checked = selectedSeverityLevels.includes(checkbox.value);
    });
    
    // Add event listeners
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const severity = e.target.value;
            if (e.target.checked) {
                if (!selectedSeverityLevels.includes(severity)) {
                    selectedSeverityLevels.push(severity);
                }
            } else {
                selectedSeverityLevels = selectedSeverityLevels.filter(s => s !== severity);
            }
            
            // Persist the selection
            localStorage.setItem('selectedSeverityLevels', JSON.stringify(selectedSeverityLevels));
            
            // Reset displayed count when filter changes
            displayedCount = 3;
            
            // Update display with new filter
            displayCVEs();
        });
    });
}

// Initialize CWE Widget with real data from API
async function initCWEWidget() {
    const cweListContent = document.getElementById('cweListContent');
    
    try {
        // Show loading state
        cweListContent.innerHTML = `
            <div class="cwe-placeholder">
                <p>📋 Loading CWE data...</p>
            </div>
        `;
        
        // Get current status filter (but not metric version - we want all metric versions for CWE stats)
        const statusParam = selectedStatusFilter !== 'accepted' ? `&statusFilter=${encodeURIComponent(selectedStatusFilter)}` : '';
        
        // Fetch CWE statistics from API (without metric version filter to get all versions)
        const response = await fetch(`/api/cves/stats/cwe?${statusParam}&limit=5`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.cweStats && data.cweStats.length > 0) {
                // Create the CWE list HTML with real data
                const cweListHTML = `
                    <ul class="cwe-list">
                        ${data.cweStats.map(cwe => `
                            <li class="cwe-item">
                                <div class="cwe-info">
                                    <div class="cwe-id">${cwe.cweId}</div>
                                    <div class="cwe-name">${getCweDescription(cwe.cweId)}</div>
                                </div>
                                <div class="cwe-count">${cwe.count}</div>
                            </li>
                        `).join('')}
                    </ul>
                `;
                
                cweListContent.innerHTML = cweListHTML;
            } else {
                // No CWE data available
                cweListContent.innerHTML = `
                    <div class="cwe-placeholder">
                        <p>📋 No CWE data available</p>
                    </div>
                `;
            }
        } else {
            throw new Error(`HTTP error: ${response.status}`);
        }
    } catch (error) {
        console.error('Error loading CWE statistics:', error);
        // Show error state
        cweListContent.innerHTML = `
            <div class="cwe-placeholder">
                <p>❌ Failed to load CWE data</p>
            </div>
        `;
    }
}

// Helper function to get CWE descriptions (common CWEs)
function getCweDescription(cweId) {
    const cweDescriptions = {
        'CWE-79': 'Cross-site Scripting (XSS)',
        'CWE-89': 'SQL Injection',
        'CWE-20': 'Improper Input Validation',
        'CWE-200': 'Information Exposure',
        'CWE-352': 'Cross-Site Request Forgery',
        'CWE-22': 'Path Traversal',
        'CWE-78': 'OS Command Injection',
        'CWE-434': 'Unrestricted Upload of File',
        'CWE-862': 'Missing Authorization',
        'CWE-863': 'Incorrect Authorization',
        'CWE-94': 'Code Injection',
        'CWE-416': 'Use After Free',
        'CWE-787': 'Out-of-bounds Write',
        'CWE-476': 'NULL Pointer Dereference',
        'CWE-190': 'Integer Overflow or Wraparound',
        'CWE-119': 'Buffer Overflow',
        'CWE-125': 'Out-of-bounds Read',
        'CWE-399': 'Resource Management Errors',
        'CWE-362': 'Concurrent Execution using Shared Resource',
        'CWE-400': 'Uncontrolled Resource Consumption'
    };
    
    return cweDescriptions[cweId] || 'Unknown CWE';
}

