# 🛡️ Vigilance Web Security Analyzer

A professional web security vulnerability scanner dashboard that analyzes software components and URLs for security vulnerabilities using the NVD (National Vulnerability Database) API.

![Security](https://img.shields.io/badge/security-web--security-orange)
![License](https://img.shields.io/badge/license-educational-blue)
![Status](https://img.shields.io/badge/status-active-success)

## 📋 Table of Contents

- [Description](#description)
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Usage](#usage)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [API Integration](#api-integration)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

## 📝 Description

**Vigilance Web Security Analyzer** is a comprehensive client-side web application designed to scan and analyze security vulnerabilities in software components and web URLs. The application integrates with the NVD (National Vulnerability Database) API to fetch real-time CVE (Common Vulnerabilities and Exposures) data and provides detailed security reports with CVSS scoring, mitigation strategies, and historical tracking.

The application offers two scanning modes:
1. **Component Scan**: Analyzes software components and versions for known CVEs using the NVD API
2. **URL Scan**: Performs mock security analysis on target URLs for common web vulnerabilities

### Key Highlights

- 🔍 **Real-time CVE Lookup**: Fetches actual vulnerability data from the NVD database
- 📊 **Interactive Dashboard**: Visual representation of vulnerabilities with severity charts and statistics
- 🎨 **Modern UI/UX**: Dark/Light theme support with responsive design
- 📈 **Historical Tracking**: Maintains a history of previous scans using localStorage
- 📥 **Export Reports**: Download comprehensive security reports in text format
- 🖨️ **Print Support**: Professional print layouts for reports
- 🚀 **Zero Configuration**: Pure client-side application, no backend required

## ✨ Features

### Core Functionality
- ✅ **Dual Scan Modes**: Toggle between component/version scanning and URL scanning
- ✅ **NVD API Integration**: Real-time CVE data fetching with fallback support
- ✅ **CVSS Scoring**: Display and prioritize vulnerabilities by Common Vulnerability Scoring System
- ✅ **Severity Classification**: Critical, High, Medium, and Low risk categorization
- ✅ **Security Headers Analysis**: Check for missing or misconfigured HTTP security headers
- ✅ **Interactive Filtering**: Filter findings by severity level
- ✅ **Sorting Options**: Sort vulnerabilities by CVSS score or severity
- ✅ **Expandable Details**: Click to view detailed vulnerability information and mitigation strategies

### User Experience
- ✅ **Theme Toggle**: Switch between dark and light themes
- ✅ **API Status Indicator**: Real-time connectivity status of NVD API
- ✅ **Progress Tracking**: Visual progress bar during scan operations
- ✅ **Historical Scans**: View the last 5 scans with key metrics
- ✅ **Export Reports**: Download security reports as text files
- ✅ **Print Support**: Optimized print layouts for reports
- ✅ **Fullscreen Charts**: View vulnerability distribution charts in fullscreen
- ✅ **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- ✅ **Local Storage**: Persists scan history and theme preferences

### Security Analysis Features
- ✅ **Overall Risk Score**: Maximum CVSS score across all findings
- ✅ **Risk Level Assessment**: Automatically categorized risk levels
- ✅ **Mitigation Strategies**: Actionable recommendations for each vulnerability
- ✅ **Affected Locations**: Detailed information about vulnerable components
- ✅ **Scan Status Indicators**: Pass/Fail status based on findings
- ✅ **Statistical Breakdown**: Count of vulnerabilities by severity


## 🚀 Installation

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)
- An internet connection (for NVD API access)
- No installation or compilation required!

### Step 1: Download or Clone the Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/vigilance-web-security-analyzer.git

# Navigate to the project directory
cd vigilance-web-security-analyzer
```

### Step 2: Verify Files

Ensure you have the following files in your project directory:
- `index.html` - Main HTML structure
- `style.css` - Application styles
- `script.js` - Application logic
- `README.md` - This file

### Step 3: That's It!

No additional installation steps required. The application is ready to run.

## 🏃 How to Run

### Method 1: Open Directly in Browser

1. Navigate to the project folder
2. Locate `index.html`
3. Double-click the file to open it in your default browser

### Method 2: Using a Local Web Server (Recommended)

#### Option A: Using Python (if installed)

```bash
# Python 3
python -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000
```

Then open: `http://localhost:8000`

#### Option B: Using Node.js (if installed)

```bash
# Install a simple HTTP server globally
npm install -g http-server

# Run the server
http-server

# Or with a specific port
http-server -p 8000
```

Then open: `http://localhost:8000`

#### Option C: Using PHP (if installed)

```bash
php -S localhost:8000
```

Then open: `http://localhost:8000`

#### Option D: Using VS Code Live Server Extension

1. Install the "Live Server" extension in VS Code
2. Right-click on `index.html`
3. Select "Open with Live Server"

### Method 3: Using Modern IDEs

Most modern IDEs (WebStorm, Atom, Sublime Text with extensions) provide built-in preview servers.

## 💻 Usage

### Component/Version Scanning

1. **Select Mode**: Ensure "Component Scan" mode is active (default)
2. **Enter Component**: Type the software component name (e.g., "Apache Tomcat")
3. **Enter Version**: Type the version number (e.g., "8.5.88")
4. **Start Scan**: Click "Start Security Scan"
5. **View Results**: Review the generated security report with CVE details

**Example:**
- Component: `Apache Tomcat`
- Version: `8.5.88`

### URL Scanning

1. **Select Mode**: Click "URL Scan" to switch modes
2. **Enter URL**: Type the target URL (e.g., "https://example.com")
3. **Start Scan**: Click "Start Security Scan"
4. **View Results**: Review the generated security report with web vulnerabilities

**Example:**
- URL: `https://example.com`

### Using the Dashboard

#### Viewing Findings
- **Filter by Severity**: Use the dropdown to filter by severity level
- **Sort Results**: Sort by CVSS score (highest first) or severity level
- **Expand Details**: Click on any finding card to view detailed information
- **View Statistics**: Check the summary cards for overall metrics

#### Exporting Reports
- Click "📥 Export Report" to download a text file with all scan results

#### Printing Reports
- Click "🖨️ Print Report" to open the browser's print dialog

#### Theme Toggle
- Click the theme toggle button (🌙/☀️) in the header to switch between dark and light themes

#### Viewing Historical Scans
- Scroll down to the "Historical Scans" section to view your last 5 scans

## 🛠️ Technologies Used

### Frontend
- **HTML5**: Semantic markup and structure
- **CSS3**: Modern styling with CSS variables, flexbox, grid, and animations
- **JavaScript (ES6+)**: 
  - Async/await for asynchronous operations
  - Fetch API for HTTP requests
  - localStorage for data persistence
  - DOM manipulation and event handling
  - Fullscreen API for chart viewing
  - Print API for report generation

### External APIs
- **NVD API v2.0**: National Vulnerability Database for CVE data
  - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - Keyword search functionality
  - Real-time CVE fetching

### Browser APIs Used
- **localStorage**: Store scan history and user preferences
- **Fetch API**: HTTP requests to NVD API
- **Fullscreen API**: Fullscreen chart viewing
- **Print API**: Browser print functionality
- **Blob API**: File generation for exports

## 📁 Project Structure

```
vigilance-web-security-analyzer/
│
├── index.html          # Main HTML structure
├── style.css           # Application styles and themes
├── script.js           # Application logic and API integration
└── README.md           # Project documentation
```

### File Descriptions

#### `index.html`
- Contains the complete HTML structure
- Defines sections for scanning, progress, and reports
- Includes semantic HTML5 elements
- Responsive meta tags and viewport configuration

#### `style.css`
- Comprehensive styling for all components
- CSS variables for theme support
- Dark and light theme implementations
- Print-specific styles
- Responsive media queries for mobile devices
- Animations and transitions

#### `script.js`
- Core application logic
- NVD API integration and CVE parsing
- CVE data fetching with error handling
- Mock data fallback system
- localStorage management
- Filtering, sorting, and rendering logic
- Theme and API status management
- Export and print functionality

## 🔌 API Integration

### NVD API v2.0

The application integrates with the NVD (National Vulnerability Database) API to fetch real CVE data.

**API Endpoint:**
```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

**Usage in Application:**
```javascript
const searchTerm = encodeURIComponent(`${component} ${version}`);
const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${searchTerm}&resultsPerPage=20`;
```

**Features:**
- Keyword-based search for component and version
- Fetches up to 20 CVEs per search
- Parses CVSS v3.1, v3.0, and v2.0 scores
- Extracts CVE descriptions and affected configurations
- Includes fallback to mock data if API is unavailable

**Note:** The NVD API may have rate limits. If requests fail, the application automatically falls back to demonstration data.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. However, please note this is an educational project.

## ⚠️ Disclaimer

**Educational Purpose Only**

This application is created for educational and demonstration purposes only. The security scans performed by this tool should not be considered comprehensive professional security assessments.

### Important Notes:
- This tool uses publicly available CVE data from the NVD database
- URL scanning uses mock data and does not perform actual security tests
- Real security assessments should be performed by qualified security professionals
- Always follow responsible disclosure practices
- Do not use this tool on systems you do not own or have explicit permission to test

### Legal Notice:
- The authors are not responsible for any misuse of this software
- Users are responsible for ensuring they have proper authorization before scanning any system
- Use this tool in accordance with all applicable laws and regulations

## 📄 License

This project is for **educational purposes only** and is provided as-is without any warranties.

## 👨‍💻 Author

Created as a demonstration of modern web development techniques with real API integration.

---

## 🙏 Acknowledgments

- **NVD (National Vulnerability Database)** for providing the CVE API
- **MITRE Corporation** for maintaining the CVE program
- All contributors to web standards and browser APIs

---

**Remember:** Always practice responsible security testing and respect user privacy and system integrity. 🛡️
