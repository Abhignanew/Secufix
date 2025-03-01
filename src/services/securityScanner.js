const axios = require("axios");
require("dotenv").config();

const OSS_INDEX_URL = "https://ossindex.sonatype.org/api/v3/component-report";
const OSS_INDEX_USER = process.env.OSS_INDEX_USER;
const OSS_INDEX_TOKEN = process.env.OSS_INDEX_TOKEN;

// Retry configuration
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

// Delay utility function
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Authentication configuration
const getAuthConfig = () => {
    if (OSS_INDEX_USER && OSS_INDEX_TOKEN) {
        return {
            auth: { 
                username: OSS_INDEX_USER, 
                password: OSS_INDEX_TOKEN 
            }
        };
    }
    return {};
};

/**
 * Scan a specific dependency for vulnerabilities using OSS Index
 * with improved error handling and retry logic
 */
async function scanDependency(packageName, version, ecosystem = "npm", retryCount = 0) {
    console.log(`🔍 Scanning ${packageName}@${version}...`);

    const purl = `pkg:${ecosystem}/${packageName}@${version}`;
    console.log(`🔗 PURL: ${purl}`);
    
    const authConfig = getAuthConfig();
    const requestConfig = {
        ...authConfig,
        headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'SecuFix-Vulnerability-Scanner'
        },
        timeout: 15000 // 15 second timeout
    };
    
    // Log request details
    console.log(`📡 API Request URL: ${OSS_INDEX_URL}`);
    console.log(`📡 Request payload: { coordinates: ["${purl}"] }`);
    
    if (Object.keys(authConfig).length > 0) {
        console.log('📡 Using authentication');
    } else {
        console.log('⚠️ No authentication provided - may be subject to rate limiting');
    }

    try {
        // Make the API request with proper formatting
        const response = await axios.post(
            OSS_INDEX_URL,
            { coordinates: [purl] },
            requestConfig
        );

        // Log successful response
        console.log(`✅ Received response for ${packageName}@${version}`);
        
        // Validate response format
        if (!response.data || !Array.isArray(response.data) || response.data.length === 0) {
            console.log(`⚠️ Unexpected response format for ${packageName}@${version}`);
            console.log(`📄 Response: ${JSON.stringify(response.data)}`);
            return [{
                package: packageName,
                version: version,
                severity: "unknown",
                title: "Scan Error",
                description: "Unexpected response format from vulnerability database"
            }];
        }

        // Process vulnerabilities if found
        if (response.data[0]?.vulnerabilities?.length > 0) {
            console.log(`❌ Found ${response.data[0].vulnerabilities.length} vulnerabilities in ${packageName}@${version}`);
            return response.data[0].vulnerabilities.map(v => ({
                package: packageName,
                version: version,
                severity: v.cvssScore >= 7 ? "high" : v.cvssScore >= 4 ? "medium" : "low",
                title: v.title,
                description: v.description,
                cvssScore: v.cvssScore,
                cve: v.cve || null,
                reference: v.reference || null
            }));
        }

        console.log(`✅ No vulnerabilities found in ${packageName}@${version}`);
        return [];
    } catch (error) {
        console.error(`❌ Error scanning ${packageName}@${version}:`);
        
        if (error.response) {
            console.error(`📉 Status: ${error.response.status}`);
            console.error(`📉 Response data:`, error.response.data);
            
            // Handle rate limiting with retry logic
            if (error.response.status === 429 && retryCount < MAX_RETRIES) {
                const waitTime = RETRY_DELAY_MS * (retryCount + 1);
                console.log(`⏳ Rate limit hit - waiting ${waitTime}ms before retry ${retryCount + 1}/${MAX_RETRIES}`);
                await delay(waitTime);
                return scanDependency(packageName, version, ecosystem, retryCount + 1);
            }
            
            // Handle authentication errors
            if ((error.response.status === 401 || error.response.status === 403) && retryCount === 0) {
                console.log(`🔒 Authentication error - check your credentials`);
            }
            
            // Handle server errors with retry
            if (error.response.status >= 500 && retryCount < MAX_RETRIES) {
                const waitTime = RETRY_DELAY_MS * (retryCount + 1);
                console.log(`⏳ Server error - waiting ${waitTime}ms before retry ${retryCount + 1}/${MAX_RETRIES}`);
                await delay(waitTime);
                return scanDependency(packageName, version, ecosystem, retryCount + 1);
            }
        } else if (error.request) {
            console.error(`📉 No response received:`, error.request);
            
            // Retry network errors
            if (retryCount < MAX_RETRIES) {
                const waitTime = RETRY_DELAY_MS * (retryCount + 1);
                console.log(`⏳ Network error - waiting ${waitTime}ms before retry ${retryCount + 1}/${MAX_RETRIES}`);
                await delay(waitTime);
                return scanDependency(packageName, version, ecosystem, retryCount + 1);
            }
        } else {
            console.error(`📉 Error:`, error.message);
        }
        
        // Return the dependency as potentially vulnerable when scan fails after all retries
        return [{
            package: packageName,
            version: version,
            severity: "unknown",
            title: "Scan Error",
            description: "Vulnerability scan failed after multiple attempts. Manual review recommended.",
            error: error.message
        }];
    }
}

/**
 * Parse package.json and scan for vulnerabilities
 */
async function scanPackageJson(content) {
    try {
        const packageJson = JSON.parse(content);
        const dependencies = {
            ...packageJson.dependencies || {},
            ...packageJson.devDependencies || {}
        };

        console.log(`📦 Found ${Object.keys(dependencies).length} dependencies to scan`);
        const vulnerabilities = [];

        // Add a small delay between requests to avoid rate limiting
        for (const [packageName, versionRange] of Object.entries(dependencies)) {
            const version = versionRange.replace(/[\^~]/g, ''); // Remove caret/tilde from versions
            const depVulnerabilities = await scanDependency(packageName, version, "npm");
            vulnerabilities.push(...depVulnerabilities);
            
            // Add a small delay between requests
            await delay(500);
        }

        return vulnerabilities;
    } catch (error) {
        console.error("❌ Error parsing package.json:", error);
        return [{
            package: "package.json",
            version: "N/A",
            severity: "unknown",
            title: "Parse Error",
            description: "Failed to parse package.json: " + error.message
        }];
    }
}

/**
 * Parse requirements.txt and scan for vulnerabilities
 */
async function scanRequirementsTxt(content) {
    try {
        const lines = content.split("\n");
        const dependencies = lines
            .map(line => line.trim())
            .filter(line => line && !line.startsWith("#"))
            .map(line => {
                // Handle various formats of Python requirements
                const equalMatch = line.match(/^([a-zA-Z0-9_.-]+)(?:==|>=|<=|~=|!=|>|<)([a-zA-Z0-9_.-]+)/);
                if (equalMatch) {
                    return { packageName: equalMatch[1], version: equalMatch[2] };
                }
                
                // Handle requirements without version
                if (line.match(/^[a-zA-Z0-9_.-]+$/)) {
                    return { packageName: line, version: "latest" };
                }
                
                return null;
            })
            .filter(dep => dep !== null);

        console.log(`📦 Found ${dependencies.length} dependencies to scan in requirements.txt`);
        const vulnerabilities = [];

        for (const { packageName, version } of dependencies) {
            // Skip dependencies without specific versions for scanning
            if (version === "latest") {
                console.log(`⚠️ Skipping ${packageName} with unspecified version`);
                continue;
            }
            
            const depVulnerabilities = await scanDependency(packageName, version, "pypi");
            vulnerabilities.push(...depVulnerabilities);
            
            // Add a small delay between requests
            await delay(500);
        }

        return vulnerabilities;
    } catch (error) {
        console.error("❌ Error parsing requirements.txt:", error);
        return [{
            package: "requirements.txt",
            version: "N/A",
            severity: "unknown",
            title: "Parse Error",
            description: "Failed to parse requirements.txt: " + error.message
        }];
    }
}

/**
 * Very basic Maven POM XML parser - can be expanded for more complex projects
 */
async function scanPomXml(content) {
    try {
        // Simple regex-based extraction - for production use a proper XML parser
        const dependencies = [];
        const depMatches = content.matchAll(/<dependency>[\s\S]*?<groupId>(.*?)<\/groupId>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>[\s\S]*?<\/dependency>/g);
        
        for (const match of depMatches) {
            if (match.length >= 4) {
                dependencies.push({
                    groupId: match[1].trim(),
                    artifactId: match[2].trim(),
                    version: match[3].trim()
                });
            }
        }
        
        console.log(`📦 Found ${dependencies.length} dependencies to scan in pom.xml`);
        const vulnerabilities = [];

        for (const { groupId, artifactId, version } of dependencies) {
            // Maven uses groupId and artifactId
            const packageName = `${groupId}:${artifactId}`;
            const depVulnerabilities = await scanDependency(packageName, version, "maven");
            vulnerabilities.push(...depVulnerabilities);
            
            // Add a small delay between requests
            await delay(500);
        }

        return vulnerabilities;
    } catch (error) {
        console.error("❌ Error parsing pom.xml:", error);
        return [{
            package: "pom.xml",
            version: "N/A",
            severity: "unknown",
            title: "Parse Error",
            description: "Failed to parse pom.xml: " + error.message
        }];
    }
}

/**
 * Scan dependencies in different file formats
 */
async function scanDependencies(fileName, content) {
    console.log(`🔍 Scanning ${fileName}...`);

    try {
        if (fileName === "package.json") {
            return await scanPackageJson(content);
        } else if (fileName === "requirements.txt") {
            return await scanRequirementsTxt(content);
        } else if (fileName === "pom.xml") {
            return await scanPomXml(content);
        } else if (fileName.endsWith('.gradle') || fileName === "build.gradle") {
            return [{
                package: fileName,
                version: "N/A",
                severity: "unknown",
                title: "Unsupported Format",
                description: "Gradle scanning is not yet implemented."
            }];
        } else if (fileName === "Gemfile" || fileName === "Gemfile.lock") {
            return [{
                package: fileName,
                version: "N/A",
                severity: "unknown",
                title: "Unsupported Format",
                description: "Ruby Gemfile scanning is not yet implemented."
            }];
        }

        console.warn(`⚠️ Unsupported file format: ${fileName}`);
        return [];
    } catch (error) {
        console.error(`❌ Unexpected error scanning ${fileName}:`, error);
        return [{
            package: fileName,
            version: "N/A", 
            severity: "unknown",
            title: "Scan Error",
            description: `Unexpected error during scan: ${error.message}`
        }];
    }
}

module.exports = {
    scanDependency,
    scanDependencies
};