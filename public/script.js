let cves = [];
let allDDoSCVEs = [];
let displayedCount = 3;
let showDDoSOnly = false;
let selectedYear = 'all';
let selectedMinScore = '0';

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
    initYearFilter(); // Initialize year filter
    initSeverityFilter(); // Initialize severity score filter
    loadCVEsOnce();
    initSeverityChart();
    initYearlyTrendsChart();
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
        const response = await fetch(`/api/cves/sample/ddos?limit=90&metricVersion=${encodeURIComponent(mappedVersion)}${yearParam}${scoreParam}`);
        
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
    console.log('Debug - allDDoSCVEs.length:', allDDoSCVEs.length, 'displayedCount:', displayedCount);
    if (allDDoSCVEs.length > displayedCount) {
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
    displayedCount = Math.min(displayedCount + increment, allDDoSCVEs.length);
    cves = allDDoSCVEs.slice(0, displayedCount);
    displayCVEs();
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
    // Refresh the pie chart, yearly trends chart, stats, and DDoS CVEs with current metric version
    await Promise.all([
        showSeverityDistribution(),
        showYearlyTrends(),
        updateStats(),
        loadDDoSCVEs()
    ]);
}

function filterDDoSOnly() {
    showDDoSOnly = !showDDoSOnly;
    const button = document.querySelector('.btn-warning, .btn-info');
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
        
        // Fetch both all CVEs and DDoS-related CVEs data in parallel
        const [allCvesResponse, ddosCvesResponse] = await Promise.all([
            fetch(`/api/cves/stats/yearly-trends?metricVersion=${encodeURIComponent(mappedVersion)}`),
            fetch(`/api/cves/stats/yearly-ddos-trends?metricVersion=${encodeURIComponent(mappedVersion)}`)
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
    searchResultsWidget.style.display = 'block';
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
    
    // Check if DDoS filter is active and CVE is not DDoS-related
    if (showDDoSOnly && !cve.ddosRelated) {
        searchResultsContent.innerHTML = `
            <div class="search-result">
                <h4>🔍 CVE Found but Filtered Out</h4>
                <p><strong>${cve.cveId}</strong> was found in the database but is not displayed because:</p>
                <ul>
                    <li>DDoS filter is currently active (🛡️ DDoS Only mode)</li>
                    <li>This CVE is not DDoS-related</li>
                </ul>
                <p><strong>DDoS Related:</strong> 
                <span style="color: #dc3545; font-weight: bold;">No</span></p>
                <p><em>Switch to "Show All" mode to view this CVE, or search for a DDoS-related CVE.</em></p>
            </div>
        `;
        return;
    }
    
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

// Allow Enter key to trigger search
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('cveSearchInput');
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchCVE();
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

