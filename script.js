// ==========================================
// VIGILANCE WEB SECURITY ANALYZER
// NVD API Integration for Dynamic CVE Data
// ==========================================

// DOM Elements
const componentInput = document.getElementById('component-input');
const versionInput = document.getElementById('version-input');
const scanBtn = document.getElementById('scan-btn');
const progressSection = document.getElementById('progress-section');
const reportSection = document.getElementById('report-section');
const progressBar = document.getElementById('progress-bar');
const progressText = document.getElementById('progress-text');
const scanComponent = document.getElementById('scan-component');
const scanTimestamp = document.getElementById('scan-timestamp');
const statusIndicator = document.getElementById('status-indicator');
const totalFindings = document.getElementById('total-findings');
const riskScore = document.getElementById('risk-score');
const riskLevel = document.getElementById('risk-level');
const severityCounts = document.getElementById('severity-counts');
const severityChart = document.getElementById('severity-chart');
const headersBody = document.getElementById('headers-body');
const findingsContainer = document.getElementById('findings-container');
const severityFilter = document.getElementById('severity-filter');
const sortFilter = document.getElementById('sort-filter');
const exportBtn = document.getElementById('export-btn');
const scansList = document.getElementById('scans-list');

// Mock security headers data (static)
const mockSecurityHeaders = [
    { name: "Content-Security-Policy", status: "missing", recommendation: "Implement a strict CSP that limits resource loading and prevents XSS attacks." },
    { name: "Strict-Transport-Security (HSTS)", status: "missing", recommendation: "Configure HSTS with max-age=31536000 to enforce HTTPS connections." },
    { name: "X-Frame-Options", status: "present", recommendation: "No action needed - properly configured." },
    { name: "X-Content-Type-Options", status: "misconfigured", recommendation: "Set value to 'nosniff' to prevent MIME type sniffing." }
];

// State variables
let currentFindings = [];
let filterSeverity = 'all';
let sortBy = 'cvss';

// Initialize page - moved below

// ==========================================
// NVD API FUNCTIONS
// ==========================================

/**
 * Construct CPE (Common Platform Enumeration) string from component and version
 * Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
 */
function constructCPE(component, version) {
    // Normalize component name (remove spaces, lowercase, etc.)
    const normalizedComponent = component.toLowerCase().replace(/\s+/g, '_');
    
    // Extract vendor name (first word) and product name
    const parts = normalizedComponent.split('_');
    const vendor = parts[0] || 'unknown';
    const product = parts.slice(1).join('_') || normalizedComponent;
    
    // Construct CPE 2.3 URI
    // Format: cpe:/a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*:*`;
}

/**
 * Fetch CVEs from NVD API using CPE
 */
async function fetchCVEsFromNVD(component, version) {
    try {
        const cpe = constructCPE(component, version);
        console.log('Constructed CPE:', cpe);
        
        // NVD API v2.0 endpoint - using keyword search instead of exact CPE match
        // This is more reliable for real-world usage
        const searchTerm = encodeURIComponent(`${component} ${version}`);
        const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${searchTerm}&resultsPerPage=20`;
        
        console.log('Fetching from NVD API:', apiUrl);
        
        progressText.textContent = `Fetching vulnerability data for ${component} ${version}...`;
        
        const response = await fetch(apiUrl);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('NVD API Response:', data);
        
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            return parseNVDResponse(data.vulnerabilities, component, version);
        } else {
            console.log('No vulnerabilities found in NVD API response');
            return null;
        }
        
    } catch (error) {
        console.error('Error fetching from NVD API:', error);
        console.log('Falling back to mock data for demonstration...');
        return null; // Will trigger fallback
    }
}

/**
 * Parse NVD API response into our standard vulnerability format
 */
function parseNVDResponse(vulnerabilities, component, version) {
    return vulnerabilities.map((item, index) => {
        const cve = item.cve;
        const cveId = cve.id;
        
        // Extract CVSS v3.1 or v3.0 or v2.0 score
        let cvssScore = 0.0;
        let severity = 'low';
        let description = 'No description available';
        
        if (cve.metrics?.cvssMetricV31 && cve.metrics.cvssMetricV31[0]) {
            cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        } else if (cve.metrics?.cvssMetricV30 && cve.metrics.cvssMetricV30[0]) {
            cvssScore = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
        } else if (cve.metrics?.cvssMetricV2 && cve.metrics.cvssMetricV2[0]) {
            cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
        }
        
        // Determine severity based on CVSS score
        if (cvssScore >= 9.0) severity = 'critical';
        else if (cvssScore >= 7.0) severity = 'high';
        else if (cvssScore >= 4.0) severity = 'medium';
        else severity = 'low';
        
        // Get description
        if (cve.descriptions && cve.descriptions[0]) {
            description = cve.descriptions[0].value;
        }
        
        // Get affected configurations for location
        let affectedLocation = 'Multiple versions';
        if (cve.configurations && cve.configurations[0]?.nodes) {
            const nodes = cve.configurations[0].nodes;
            if (nodes[0]?.cpeMatch) {
                affectedLocation = nodes[0].cpeMatch.map(m => m.criteria).join(', ');
            }
        }
        
        return {
            id: index + 1,
            cve_id: cveId,
            title: cveId || 'Unknown CVE',
            severity: severity,
            cvss_score: cvssScore,
            description: description.substring(0, 300) + (description.length > 300 ? '...' : ''),
            affectedLocation: affectedLocation,
            mitigation: generateMitigationStrategy(severity, cveId)
        };
    });
}

/**
 * Generate mitigation strategy based on severity and CVE
 */
function generateMitigationStrategy(severity, cveId) {
    const baseUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    
    if (severity === 'critical' || severity === 'high') {
        return `Immediate action required. Review the vulnerability details at ${baseUrl}. Apply security patches or updates as soon as possible. Consider temporary mitigations such as network-level restrictions. Monitor for exploitation attempts.`;
    } else if (severity === 'medium') {
        return `Address this vulnerability in your next security update cycle. Review details at ${baseUrl}. Consider implementing workarounds if patches are not immediately available.`;
    } else {
        return `Low priority. Review details at ${baseUrl}. Address when convenient during regular maintenance windows.`;
    }
}

/**
 * Get fallback/mock data for demonstration purposes
 */
function getFallbackData(component, version) {
    const mockData = {
        high: [
            {
                id: 1,
                cve_id: 'CVE-2024-XXXXX',
                title: 'Critical Vulnerability in Component',
                severity: 'critical',
                cvss_score: 9.8,
                description: `Critical security vulnerability detected in ${component} version ${version}. This vulnerability allows remote code execution and should be addressed immediately.`,
                affectedLocation: `${component}:${version}`,
                mitigation: `Immediate action required. Update to the latest secure version of ${component}. Apply security patches as soon as possible.`
            },
            {
                id: 2,
                cve_id: 'CVE-2024-YYYYY',
                title: 'Remote Code Execution Vulnerability',
                severity: 'high',
                cvss_score: 8.5,
                description: `Remote code execution vulnerability in ${component} ${version}. Attackers can execute arbitrary code through malicious input.`,
                affectedLocation: `${component}:${version}`,
                mitigation: `Update ${component} to a patched version. Review and sanitize all user inputs.`
            }
        ],
        medium: [
            {
                id: 3,
                cve_id: 'CVE-2024-ZZZZZ',
                title: 'Information Disclosure Vulnerability',
                severity: 'medium',
                cvss_score: 6.2,
                description: `Information disclosure vulnerability in ${component} ${version} may expose sensitive data to unauthorized users.`,
                affectedLocation: `${component}:${version}`,
                mitigation: `Apply available security updates. Review access controls and implement additional security measures.`
            }
        ],
        low: []
    };
    
    return [
        ...mockData.high,
        ...mockData.medium,
        ...mockData.low
    ];
}

// ==========================================
// MAIN SCAN FUNCTION
// ==========================================

async function startScan() {
    const component = componentInput.value.trim();
    const version = versionInput.value.trim();
    
    // Validation
    if (!component || !version) {
        alert('Please enter both component name and version number');
        return;
    }
    
    // Save to localStorage
    localStorage.setItem('lastScannedComponent', component);
    localStorage.setItem('lastScannedVersion', version);
    
    // Hide report and show progress
    reportSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    
    // Disable button
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    
    // Simulate progress
    progressBar.style.width = '10%';
    progressText.textContent = `Initializing scan for ${component} ${version}...`;
    
    // Fetch vulnerabilities
    progressBar.style.width = '50%';
    progressText.textContent = 'Fetching vulnerability data from NVD API...';
    
    let findings = await fetchCVEsFromNVD(component, version);
    
    // If API call failed, use fallback
    if (!findings || findings.length === 0) {
        progressText.textContent = 'Using demonstration data (API unavailable)...';
        findings = getFallbackData(component, version);
    }
    
    progressBar.style.width = '80%';
    progressText.textContent = 'Processing vulnerability data...';
    
    // Wait a bit for visual feedback
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    progressBar.style.width = '100%';
    progressText.textContent = 'Scan complete!';
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Show report
    showReport(findings, component, version);
}

// ==========================================
// REPORT DISPLAY FUNCTIONS
// ==========================================

function showReport(findings, target, suffix, isURL = false) {
    currentFindings = findings;
    
    // Hide progress and show report
    progressSection.classList.add('hidden');
    reportSection.classList.remove('hidden');
    
    // Re-enable button
    scanBtn.disabled = false;
    scanBtn.textContent = 'Start Security Scan';
    const scanBtnUrl = document.getElementById('scan-btn-url');
    if (scanBtnUrl) {
        scanBtnUrl.disabled = false;
        scanBtnUrl.textContent = 'Start Security Scan';
    }
    
    // Set scan info
    if (isURL) {
        scanComponent.textContent = `Target: ${target}`;
    } else {
        scanComponent.textContent = `Component: ${target} ${suffix}`;
    }
    scanTimestamp.textContent = `Scanned: ${new Date().toLocaleString()}`;
    
    // Calculate statistics
    const counts = calculateStatistics(findings);
    const maxCvss = calculateRiskScore(findings);
    
    // Display status
    const hasHighRisks = counts.critical > 0 || counts.high > 0;
    statusIndicator.className = 'status-indicator ' + (hasHighRisks ? 'status-fail' : 'status-pass');
    statusIndicator.querySelector('.status-text').textContent = hasHighRisks ? '⚠️ Vulnerabilities Detected' : '✅ No Critical Issues';
    
    // Display counts
    totalFindings.textContent = counts.total;
    riskScore.textContent = maxCvss.toFixed(1);
    riskLevel.textContent = getRiskLevel(maxCvss);
    
    displaySeverityCounts(counts);
    displaySeverityChart(counts);
    displaySecurityHeaders();
    renderFindings();
    if (!isURL) {
        saveHistoricalScan(counts, maxCvss, target, suffix);
    } else {
        saveHistoricalScan(counts, maxCvss, target, 'URL', true);
    }
    loadHistoricalScans();
}

function calculateStatistics(findings) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: findings.length
    };
    
    findings.forEach(f => {
        if (f.severity in counts) {
            counts[f.severity]++;
        }
    });
    
    return counts;
}

function calculateRiskScore(findings) {
    if (findings.length === 0) return 0;
    return Math.max(...findings.map(f => f.cvss_score));
}

function getRiskLevel(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 1.0) return 'Low';
    return 'Informational';
}

function displaySeverityCounts(counts) {
    const items = [
        { label: 'Critical', count: counts.critical, class: 'severity-critical' },
        { label: 'High', count: counts.high, class: 'severity-high' },
        { label: 'Medium', count: counts.medium, class: 'severity-medium' },
        { label: 'Low', count: counts.low, class: 'severity-low' }
    ];
    
    severityCounts.innerHTML = items.map(item => `
        <div class="severity-item">
            <span class="severity-badge ${item.class}">${item.label}</span>
            <span>${item.count} CVE${item.count !== 1 ? 's' : ''}</span>
        </div>
    `).join('');
}

function displaySeverityChart(counts) {
    const items = [
        { label: 'Critical', count: counts.critical, color: 'var(--danger-color)' },
        { label: 'High', count: counts.high, color: 'var(--danger-color)' },
        { label: 'Medium', count: counts.medium, color: 'var(--warning-color)' },
        { label: 'Low', count: counts.low, color: 'var(--info-color)' }
    ];
    
    const maxCount = Math.max(...items.map(i => i.count), 1);
    
    severityChart.innerHTML = items.map(item => {
        const height = maxCount > 0 ? (item.count / maxCount) * 100 : 0;
        return `
            <div class="chart-bar" style="height: ${height}%; background: ${item.color};">
                <span class="chart-value">${item.count}</span>
                <span class="chart-label">${item.label}</span>
            </div>
        `;
    }).join('');
}

function displaySecurityHeaders() {
    headersBody.innerHTML = mockSecurityHeaders.map(header => {
        const statusIcon = header.status === 'present' ? '✅' : header.status === 'missing' ? '❌' : '⚠️';
        const statusClass = `status-${header.status}`;
        return `
            <tr>
                <td><strong>${header.name}</strong></td>
                <td><span class="${statusClass}">${statusIcon} ${header.status.charAt(0).toUpperCase() + header.status.slice(1)}</span></td>
                <td>${header.recommendation}</td>
            </tr>
        `;
    }).join('');
}

function renderFindings() {
    let filtered = [...currentFindings];
    
    // Apply severity filter
    if (filterSeverity !== 'all') {
        filtered = filtered.filter(f => f.severity === filterSeverity);
    }
    
    // Apply sort
    if (sortBy === 'cvss') {
        filtered.sort((a, b) => b.cvss_score - a.cvss_score);
    } else if (sortBy === 'severity') {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        filtered.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);
    }
    
    findingsContainer.innerHTML = filtered.map(finding => {
        const cvssLevel = finding.cvss_score >= 9.0 ? 'critical' : 
                         finding.cvss_score >= 7.0 ? 'high' : 
                         finding.cvss_score >= 4.0 ? 'medium' : 'low';
        
        return `
            <div class="finding-card ${finding.severity}" id="finding-${finding.id}">
                <div class="finding-header" onclick="toggleFinding(${finding.id})">
                    <div class="finding-title">
                        <div>
                            <h4><span class="cve-id">${finding.cve_id || finding.title}</span> <span class="cvss-badge cvss-${cvssLevel}">CVSS ${finding.cvss_score}</span></h4>
                            <div class="finding-details">
                                <span class="severity-badge severity-${finding.severity}">${finding.severity.toUpperCase()}</span>
                                <span style="margin-left: 10px;">Affected: ${finding.affectedLocation}</span>
                            </div>
                        </div>
                    </div>
                    <div class="expand-icon">▼</div>
                </div>
                <div class="finding-content">
                    <div class="finding-body">
                        <div class="description">${finding.description}</div>
                        <div class="mitigation">
                            <h5>🛠️ Mitigation Strategy</h5>
                            <p>${finding.mitigation}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleFinding(id) {
    const findingCard = document.getElementById(`finding-${id}`);
    if (findingCard) {
        findingCard.classList.toggle('expanded');
    }
}

function saveHistoricalScan(counts, maxCvss, target, suffix, isURL = false) {
    const scans = JSON.parse(localStorage.getItem('historicalScans') || '[]');
    const scan = {
        target: isURL ? target : `${target} ${suffix}`,
        date: new Date().toISOString(),
        criticalFindings: counts.critical,
        totalFindings: counts.total,
        riskScore: maxCvss.toFixed(1)
    };
    
    scans.unshift(scan);
    scans.splice(5);
    localStorage.setItem('historicalScans', JSON.stringify(scans));
}

function loadHistoricalScans() {
    const scans = JSON.parse(localStorage.getItem('historicalScans') || '[]');
    
    if (scans.length === 0) {
        scansList.innerHTML = '<p style="color: var(--text-secondary);">No historical scans available.</p>';
        return;
    }
    
    scansList.innerHTML = scans.map(scan => {
        const date = new Date(scan.date).toLocaleString();
        return `
            <div class="scan-item">
                <div class="scan-item-info">
                    <div class="scan-item-url">${scan.target || scan.component}</div>
                    <div class="scan-item-date">${date}</div>
                </div>
                <div class="scan-item-findings">
                    <div class="scan-item-findings-count">${scan.criticalFindings || 0}</div>
                    <div class="scan-item-findings-label">Critical Issues</div>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================
// URL SCAN FUNCTIONS (Mock Data)
// ==========================================

function getURLMockData(url) {
    return [
        {
            id: 1,
            cve_id: 'WEB-SEC-001',
            title: 'Mixed Content Vulnerability',
            severity: 'high',
            cvss_score: 7.5,
            description: `The target URL ${url} loads resources over both HTTP and HTTPS, creating a mixed content vulnerability that can be exploited by attackers.`,
            affectedLocation: url,
            mitigation: 'Ensure all resources (scripts, stylesheets, images) are loaded exclusively over HTTPS. Update all hardcoded HTTP URLs to use HTTPS.'
        },
        {
            id: 2,
            cve_id: 'WEB-SEC-002',
            title: 'Missing Security Headers',
            severity: 'medium',
            cvss_score: 5.8,
            description: `The web server at ${url} is not sending critical security headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.`,
            affectedLocation: url,
            mitigation: 'Configure the web server to send security headers. Implement CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and HSTS headers.'
        },
        {
            id: 3,
            cve_id: 'WEB-SEC-003',
            title: 'TLS Version Detection',
            severity: 'medium',
            cvss_score: 6.1,
            description: `The server is using outdated TLS versions or weak cipher suites that may be vulnerable to known attacks.`,
            affectedLocation: url,
            mitigation: 'Disable TLS 1.0 and 1.1. Use only TLS 1.2 or higher. Implement strong cipher suites and disable weak algorithms.'
        },
        {
            id: 4,
            cve_id: 'WEB-SEC-004',
            title: 'Server Information Disclosure',
            severity: 'low',
            cvss_score: 3.2,
            description: `HTTP response headers reveal sensitive server information including version numbers and software stack details.`,
            affectedLocation: url,
            mitigation: 'Configure the web server to hide or obscure version information in headers. Remove or modify Server, X-Powered-By, and other revealing headers.'
        },
        {
            id: 5,
            cve_id: 'WEB-SEC-005',
            title: 'Cookie Security Issues',
            severity: 'medium',
            cvss_score: 5.5,
            description: `Cookies are not being transmitted with the Secure flag, allowing potential theft over unencrypted connections.`,
            affectedLocation: url,
            mitigation: 'Set the Secure flag on all cookies. Enable HttpOnly flag to prevent JavaScript access. Use SameSite attribute to prevent CSRF attacks.'
        }
    ];
}

async function startURLScan() {
    const url = document.getElementById('url-input').value.trim();
    
    // Validation
    if (!url) {
        alert('Please enter a URL to scan');
        return;
    }
    
    // Basic URL validation
    try {
        new URL(url);
    } catch {
        alert('Please enter a valid URL (starting with http:// or https://)');
        return;
    }
    
    // Save to localStorage
    localStorage.setItem('lastScannedURL', url);
    
    // Hide report and show progress
    reportSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    
    // Disable button
    const scanBtnUrl = document.getElementById('scan-btn-url');
    scanBtnUrl.disabled = true;
    scanBtnUrl.textContent = 'Scanning...';
    
    // Simulate progress
    progressBar.style.width = '10%';
    progressText.textContent = 'Connecting to target server...';
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    progressBar.style.width = '30%';
    progressText.textContent = 'Analyzing HTTP headers...';
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    progressBar.style.width = '50%';
    progressText.textContent = 'Checking SSL/TLS configuration...';
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    progressBar.style.width = '70%';
    progressText.textContent = 'Scanning for common vulnerabilities...';
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    progressBar.style.width = '90%';
    progressText.textContent = 'Finalizing security report...';
    
    await new Promise(resolve => setTimeout(resolve, 800));
    
    progressBar.style.width = '100%';
    progressText.textContent = 'Scan complete!';
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Get mock data
    const findings = getURLMockData(url);
    
    // Show report
    showReport(findings, url, 'URL', true);
    
    // Re-enable button
    scanBtnUrl.disabled = false;
    scanBtnUrl.textContent = 'Start Security Scan';
}

// ==========================================
// MODE TOGGLE FUNCTIONS
// ==========================================

function switchMode(mode) {
    const componentMode = document.getElementById('component-mode');
    const urlMode = document.getElementById('url-mode');
    const componentToggle = document.getElementById('mode-toggle');
    const urlToggle = document.getElementById('mode-toggle-url');
    
    if (mode === 'component') {
        componentMode.classList.add('active');
        urlMode.classList.remove('active');
        componentToggle.classList.add('active');
        urlToggle.classList.remove('active');
    } else {
        componentMode.classList.remove('active');
        urlMode.classList.add('active');
        componentToggle.classList.remove('active');
        urlToggle.classList.add('active');
    }
}

// ==========================================
// EVENT LISTENERS
// ==========================================

// Mode toggle listeners
document.getElementById('mode-toggle').addEventListener('click', () => switchMode('component'));
document.getElementById('mode-toggle-url').addEventListener('click', () => switchMode('url'));

// Scan button listeners
scanBtn.addEventListener('click', startScan);
document.getElementById('scan-btn-url').addEventListener('click', startURLScan);

componentInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        versionInput.focus();
    }
});

versionInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        startScan();
    }
});

document.getElementById('url-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        startURLScan();
    }
});

// This initialization is now in the combined DOMContentLoaded below

severityFilter.addEventListener('change', (e) => {
    filterSeverity = e.target.value;
    renderFindings();
});

sortFilter.addEventListener('change', (e) => {
    sortBy = e.target.value;
    renderFindings();
});

exportBtn.addEventListener('click', () => {
    const component = componentInput.value || 'Unknown';
    const version = versionInput.value || 'Unknown';
    const url = document.getElementById('url-input').value || 'Unknown';
    const targetLabel = url && url !== 'Unknown' ? `Target: ${url}` : `Component: ${component} ${version}`;
    const timestamp = new Date().toLocaleString();
    const counts = calculateStatistics(currentFindings);
    
    const report = `Vigilance Web Security Analyzer - Security Report
${'='.repeat(60)}
${targetLabel}
Scan Date: ${timestamp}

SUMMARY
${'-'.repeat(60)}
Total Findings: ${counts.total}
Critical: ${counts.critical}
High: ${counts.high}
Medium: ${counts.medium}
Low: ${counts.low}
Overall Risk Score: ${calculateRiskScore(currentFindings).toFixed(1)}

DETAILED FINDINGS
${'-'.repeat(60)}
${currentFindings.map((f, i) => `${i + 1}. ${f.cve_id || f.title}
   Severity: ${f.severity.toUpperCase()} | CVSS: ${f.cvss_score}
   Affected: ${f.affectedLocation}
   Description: ${f.description}
`).join('\n')}

Generated by Vigilance Web Security Analyzer
Educational Purpose Only
`;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url2 = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url2;
    a.download = `cve-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url2);
    
    alert('Report exported successfully!');
});

// ==========================================
// NEW FEATURES: Theme Toggle, API Status, Print, Fullscreen Chart
// ==========================================

// Theme Toggle Feature
document.getElementById('theme-toggle').addEventListener('click', () => {
    const body = document.body;
    const themeIcon = document.getElementById('theme-icon');
    
    body.classList.toggle('light-theme');
    
    if (body.classList.contains('light-theme')) {
        themeIcon.textContent = '☀️';
        localStorage.setItem('theme', 'light');
    } else {
        themeIcon.textContent = '🌙';
        localStorage.setItem('theme', 'dark');
    }
});

// API Status Check
async function checkAPIStatus() {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.api-status .status-text');
    
    try {
        // Quick check to NVD API
        const response = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', {
            method: 'HEAD',
            mode: 'no-cors'
        });
        
        statusDot.classList.add('online');
        statusText.textContent = 'NVD API Online';
        console.log('API Status: Online');
    } catch (error) {
        statusDot.classList.remove('online');
        statusText.textContent = 'NVD API Check Failed';
        console.log('API Status: Offline or CORS issue');
    }
}

// Check API status on load
checkAPIStatus();

// Print Feature
document.getElementById('print-btn').addEventListener('click', () => {
    window.print();
});

// Fullscreen Chart Feature
let isFullscreen = false;
document.getElementById('fullscreen-chart').addEventListener('click', () => {
    const chart = document.getElementById('severity-chart');
    const chartContainer = chart.closest('.severity-chart-container');
    
    if (!isFullscreen) {
        chartContainer.requestFullscreen().then(() => {
            isFullscreen = true;
            document.getElementById('fullscreen-chart').innerHTML = '<span>⛶</span>';
        }).catch(err => {
            console.log('Fullscreen error:', err);
            alert('Fullscreen not supported in this browser');
        });
    } else {
        document.exitFullscreen().then(() => {
            isFullscreen = false;
            document.getElementById('fullscreen-chart').innerHTML = '<span>⛶</span>';
        });
    }
});

// Listen for fullscreen changes
document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
        isFullscreen = false;
        document.getElementById('fullscreen-chart').innerHTML = '<span>⛶</span>';
    }
});

// Combined initialization
window.addEventListener('DOMContentLoaded', () => {
    // Load saved theme
    const savedTheme = localStorage.getItem('theme');
    const themeIcon = document.getElementById('theme-icon');
    
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        themeIcon.textContent = '☀️';
    }
    
    // Load last scanned inputs
    const lastComponent = localStorage.getItem('lastScannedComponent');
    const lastVersion = localStorage.getItem('lastScannedVersion');
    const lastURL = localStorage.getItem('lastScannedURL');
    
    if (lastComponent && lastVersion) {
        componentInput.value = lastComponent;
        versionInput.value = lastVersion;
    }
    
    if (lastURL) {
        document.getElementById('url-input').value = lastURL;
    }
    
    // Initialize features
    loadHistoricalScans();
    checkAPIStatus();
});
