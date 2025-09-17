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

function updateStats() {
    const totalCVEs = cves.length;
    const criticalCVEs = cves.filter(c => c.severity === 'CRITICAL').length;
    const avgCVSS = cves.length > 0 ? (cves.reduce((sum, c) => sum + c.cvssScore, 0) / cves.length).toFixed(1) : '0.0';
    const activeCVEs = cves.filter(c => c.status === 'ACTIVE').length;
    
    document.getElementById('totalCVEs').textContent = totalCVEs;
    document.getElementById('criticalCVEs').textContent = criticalCVEs;
    document.getElementById('avgCVSS').textContent = avgCVSS;
    document.getElementById('activeCVEs').textContent = activeCVEs;
}


async function refreshData() {
    // Only refresh the pie chart with current metric version
    await showSeverityDistribution();
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
        type: 'doughnut',
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
        type: 'doughnut',
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

    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const labels = [];
    const data = [];

    order.forEach((k) => {
        if (distribution[k] !== undefined) {
            labels.push(k);
            data.push(distribution[k]);
        }
    });

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


// Close modal when clicking outside
window.onclick = function(event) {
    const randomModal = document.getElementById('randomCveModal');
    if (event.target === randomModal) {
        closeRandomModal();
    }
}

// Random CVE functionality
async function getRandomCVE() {
    const modal = document.getElementById('randomCveModal');
    const content = document.getElementById('randomCveContent');
    
    // Show modal with loading state
    modal.style.display = 'block';
    content.innerHTML = '<div class="loading">🎲 Fetching random CVE from NVD API...</div>';
    
    try {
        const metricVersion = window.currentMetricVersion || 'latest';
        const mappedVersion = mapMetricVersion(metricVersion);
        const response = await fetch(`/api/cves/random/nvd?metricVersion=${encodeURIComponent(mappedVersion)}`);
        const data = await response.json();
        
        if (data.success) {
            const cve = data.cve;
            const severityClass = `severity-${cve.severity.toLowerCase()}`;
            const statusClass = `status-${cve.status.toLowerCase()}`;
            
            content.innerHTML = `
                <div class="random-cve-display">
                    <h3>${cve.cveId} - ${cve.title}</h3>
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
                    <div class="cve-info"><strong>Modified:</strong> ${formatDate(cve.modifiedDate)}</div>
                    <div class="affected-products">
                        <strong>Affected Products:</strong> ${cve.affectedProducts.join(', ')}
                    </div>
                    <div class="references">
                        <strong>References:</strong>
                        ${cve.references.map(ref => `<a href="${ref}" target="_blank">${ref}</a>`).join('')}
                    </div>
                </div>
                <div class="api-info">
                    <h4>📊 API Information</h4>
                    <p><strong>Total Results:</strong> ${data.apiInfo.totalResults.toLocaleString()}</p>
                    <p><strong>Results Per Page:</strong> ${data.apiInfo.resultsPerPage}</p>
                    <p><strong>API Timestamp:</strong> ${new Date(data.apiInfo.timestamp).toLocaleString()}</p>
                </div>
            `;
        } else {
            content.innerHTML = `
                <div class="loading" style="color: #dc3545;">
                    ❌ Error: ${data.error || 'Failed to fetch random CVE'}
                </div>
            `;
        }
    } catch (error) {
        console.error('Error fetching random CVE:', error);
        content.innerHTML = `
            <div class="loading" style="color: #dc3545;">
                ❌ Error: Failed to connect to NVD API
            </div>
        `;
    }
}

function closeRandomModal() {
    document.getElementById('randomCveModal').style.display = 'none';
} 