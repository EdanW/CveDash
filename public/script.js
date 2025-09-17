let cves = [];
let editingId = null;
let showDDoSOnly = false;

// Load CVEs on page load
document.addEventListener('DOMContentLoaded', () => {
    loadCVEs();
    setDefaultDates();
    initSeverityChart();
    initMetricToggle();
});

async function loadCVEs() {
    try {
        const response = await fetch('/api/cves');
        cves = await response.json();
        displayCVEs();
        updateStats();
    } catch (error) {
        console.error('Error loading CVEs:', error);
    }
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
            <div class="card-actions">
                <button class="btn btn-primary" onclick="editCVE('${cve.id}')">Edit</button>
                <button class="btn btn-danger" onclick="deleteCVE('${cve.id}')">Delete</button>
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

function openAddModal() {
    editingId = null;
    document.getElementById('modalTitle').textContent = 'Add New CVE';
    document.getElementById('cveForm').reset();
    setDefaultDates();
    document.getElementById('cveModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('cveModal').style.display = 'none';
}

function setDefaultDates() {
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('publishedDate').value = today;
    document.getElementById('lastModifiedDate').value = today;
}

async function editCVE(id) {
    const cve = cves.find(c => c.id === id);
    if (!cve) return;
    
    editingId = id;
    document.getElementById('modalTitle').textContent = 'Edit CVE';
    document.getElementById('cveId').value = cve.cveId;
    document.getElementById('title').value = cve.title;
    document.getElementById('description').value = cve.description;
    document.getElementById('severity').value = cve.severity;
    document.getElementById('cvssScore').value = cve.cvssScore;
    document.getElementById('attackVector').value = cve.attackVector;
    document.getElementById('affectedProducts').value = cve.affectedProducts.join(', ');
    document.getElementById('publishedDate').value = cve.publishedDate;
    document.getElementById('lastModifiedDate').value = cve.lastModifiedDate;
    document.getElementById('status').value = cve.status;
    document.getElementById('references').value = cve.references.join('\n');
    document.getElementById('ddosRelated').checked = cve.ddosRelated;
    
    document.getElementById('cveModal').style.display = 'block';
}

async function deleteCVE(id) {
    if (!confirm('Are you sure you want to delete this CVE?')) return;
    
    try {
        await fetch(`/api/cves/${id}`, { method: 'DELETE' });
        await loadCVEs();
    } catch (error) {
        console.error('Error deleting CVE:', error);
    }
}

async function refreshData() {
    await loadCVEs();
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
    try {
        const response = await fetch('/api/cves/stats/severity');
        const data = await response.json();
        if (!response.ok || !data.success) {
            alert('Failed to load severity distribution');
            return;
        }
        const dist = data.distribution || {};
        renderSeverityChart(dist, data.metricVersion);
    } catch (e) {
        console.error('Error fetching severity distribution', e);
    }
}

// Initialize and render severity pie chart
let severityChartInstance = null;

function initSeverityChart() {
    // Fetch immediately on load
    showSeverityDistribution();
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
                    text: `Severity Distribution (Metric ${metricVersion})`,
                    color: '#ffffff'
                }
            },
            layout: { padding: 0 },
            responsive: true
        }
    });
}

// Metric version toggle (UI only; no data logic yet)
function initMetricToggle() {
    const select = document.getElementById('metricVersionSelect');
    if (!select) return;
    // Persist selection in-memory for now
    window.currentMetricVersion = select.value || 'latest';
    select.addEventListener('change', (e) => {
        window.currentMetricVersion = e.target.value;
        // Hook: later we will refetch/update charts and lists based on selection
        // For now, no logic is executed
    });
}

// Form submission
document.getElementById('cveForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        cveId: document.getElementById('cveId').value,
        title: document.getElementById('title').value,
        description: document.getElementById('description').value,
        severity: document.getElementById('severity').value,
        cvssScore: document.getElementById('cvssScore').value,
        attackVector: document.getElementById('attackVector').value,
        affectedProducts: document.getElementById('affectedProducts').value.split(',').map(p => p.trim()),
        publishedDate: document.getElementById('publishedDate').value,
        lastModifiedDate: document.getElementById('lastModifiedDate').value,
        status: document.getElementById('status').value,
        references: document.getElementById('references').value.split('\n').filter(r => r.trim()),
        ddosRelated: document.getElementById('ddosRelated').checked
    };
    
    try {
        const url = editingId ? `/api/cves/${editingId}` : '/api/cves';
        const method = editingId ? 'PUT' : 'POST';
        
        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        if (response.ok) {
            closeModal();
            await loadCVEs();
        }
    } catch (error) {
        console.error('Error saving CVE:', error);
    }
});

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('cveModal');
    const randomModal = document.getElementById('randomCveModal');
    if (event.target === modal) {
        closeModal();
    }
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
        const response = await fetch('/api/cves/random/nvd');
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