const axios = require("axios");
require("dotenv").config();

/**
 * Utility function to delay API requests to prevent rate limiting
 * @param {number} ms - Milliseconds to delay
 */
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Fetch the latest secure version of a package
 * @param {string} packageName - The name of the package
 * @param {string} currentVersion - The current version with vulnerability
 * @param {string} ecosystem - The package ecosystem (npm, pypi, etc.)
 * @returns {Promise<{secureVersion: string, updateCommand: string}>}
 */
async function fetchSecureVersion(packageName, currentVersion, ecosystem = "npm") {
    console.log(`🔍 Fetching secure version for ${packageName}@${currentVersion}...`);
    
    try {
        let secureVersion;
        let updateCommand;
        
        if (ecosystem === "npm") {
            const response = await axios.get(`https://registry.npmjs.org/${packageName}`, { timeout: 5000 });
            const versions = Object.keys(response.data.versions);
            
            const newerVersions = versions
                .filter(v => v.match(/^\d+\.\d+\.\d+$/)) // Ensure valid semantic versioning
                .filter(v => v > currentVersion) // Keep only newer versions
                .sort();
            
            secureVersion = newerVersions[0] || versions[versions.length - 1];
            updateCommand = `npm install ${packageName}@${secureVersion}`;
        } else if (ecosystem === "pypi") {
            const response = await axios.get(`https://pypi.org/pypi/${packageName}/json`, { timeout: 5000 });
            const releases = Object.keys(response.data.releases);
            
            const stableReleases = releases
                .filter(v => v.match(/^\d+\.\d+\.\d+$/))
                .sort();
            
            secureVersion = stableReleases[stableReleases.length - 1];
            updateCommand = `pip install ${packageName}==${secureVersion}`;
        }
        
        return { secureVersion, updateCommand };
    } catch (error) {
        console.error(`❌ Error fetching secure version for ${packageName}:`, error.message);
        return {
            secureVersion: "latest",
            updateCommand: ecosystem === "npm" 
                ? `npm install ${packageName}@latest` 
                : `pip install --upgrade ${packageName}`
        };
    }
}

/**
 * Scan dependencies and recommend secure versions
 * @param {string} fileName - Name of dependency file
 * @param {string} content - Content of dependency file
 * @returns {Promise<Array>} - Array of dependencies with secure versions
 */
async function fetchSecureDependencies(fileName, content) {
    console.log(`🔍 Analyzing ${fileName} for secure dependencies...`);
    
    let dependencies = [];
    let ecosystem = "npm";
    
    if (fileName === "package.json") {
        const packageJson = JSON.parse(content);
        const allDeps = {
            ...packageJson.dependencies || {},
            ...packageJson.devDependencies || {}
        };
        
        dependencies = Object.entries(allDeps).map(([name, version]) => ({
            packageName: name,
            version: version.replace(/[^0-9.]/g, '')
        }));
    } else if (fileName === "requirements.txt") {
        ecosystem = "pypi";
        
        const lines = content.split("\n");
        dependencies = lines
            .map(line => line.trim())
            .filter(line => line && !line.startsWith("#"))
            .map(line => {
                const parts = line.split("==");
                return parts.length === 2 
                    ? { packageName: parts[0], version: parts[1] } 
                    : null;
            })
            .filter(dep => dep !== null);
    }
    
    const results = [];
    for (const { packageName, version } of dependencies) {
        const { secureVersion, updateCommand } = await fetchSecureVersion(packageName, version, ecosystem);
        console.log(`✅ ${packageName}: ${version} → ${secureVersion}`);
        results.push({ packageName, currentVersion: version, secureVersion, updateCommand, isSecure: secureVersion === version });
        await delay(1000); // Prevent API rate limiting
    }
    
    console.log("📜 Final Results:", results);
    return results;
}

/**
 * Generate updated dependency files with secure versions
 * @param {string} fileName - Name of dependency file
 * @param {string} content - Content of dependency file
 * @param {Array} secureVersions - Array of secure versions
 * @returns {string} - Updated file content
 */
function generateSecureFile(fileName, content, secureVersions) {
    if (fileName === "package.json") {
        const packageJson = JSON.parse(content);
        
        if (packageJson.dependencies) {
            secureVersions.forEach(({ packageName, secureVersion }) => {
                if (packageJson.dependencies[packageName]) {
                    packageJson.dependencies[packageName] = `^${secureVersion}`;
                }
            });
        }
        
        if (packageJson.devDependencies) {
            secureVersions.forEach(({ packageName, secureVersion }) => {
                if (packageJson.devDependencies[packageName]) {
                    packageJson.devDependencies[packageName] = `^${secureVersion}`;
                }
            });
        }
        
        return JSON.stringify(packageJson, null, 2);
    } else if (fileName === "requirements.txt") {
        const secureMap = secureVersions.reduce((map, { packageName, secureVersion }) => {
            map[packageName] = secureVersion;
            return map;
        }, {});
        
        return content.split("\n").map(line => {
            const parts = line.split("==");
            if (parts.length !== 2) return line;
            const packageName = parts[0];
            return secureMap[packageName] ? `${packageName}==${secureMap[packageName]}` : line;
        }).join("\n");
    }
    
    return content;
}

module.exports = {
    fetchSecureVersion,
    fetchSecureDependencies,
    generateSecureFile
};
