const axios = require("axios");
const { scanDependencies } = require("./securityScanner");
const { suggestFix } = require("./geminiService");
require("dotenv").config();

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

function extractRepoDetails(repoUrl) {
    const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) {
        throw new Error("❌ Invalid GitHub URL");
    }
    return { owner: match[1], repo: match[2].replace('.git', '') };
}

async function fetchDependencyFiles(owner, repo) {
    console.log(`🔍 Fetching files from ${owner}/${repo}...`);
    
    const url = `https://api.github.com/repos/${owner}/${repo}/contents`;
    
    try {
        const response = await axios.get(url, {
            headers: { 
                Authorization: `token ${GITHUB_TOKEN}`,
                Accept: 'application/vnd.github.v3+json'
            }
        });

        // Filter only dependency files
        const dependencyFiles = response.data.filter(file =>
            ["package.json", "requirements.txt", "pom.xml"].includes(file.name)
        );

        console.log(`✅ Found ${dependencyFiles.length} dependency files:`, dependencyFiles.map(f => f.name));

        if (dependencyFiles.length === 0) {
            console.warn("⚠️ No dependency files found!");
            return [];
        }

        // Fetch and return file content
        return Promise.all(dependencyFiles.map(async file => {
            const fileContent = await fetchFileContent(owner, repo, file.path);
            console.log(`📄 ${file.name} content:\n${fileContent.substring(0, 500)}...`); // Log first 500 chars
            return { name: file.name, content: fileContent };
        }));
    } catch (error) {
        console.error(`❌ Error fetching repository contents:`, error.message);
        throw new Error(`Failed to fetch repository contents: ${error.message}`);
    }
}

async function fetchFileContent(owner, repo, path) {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
    
    try {
        console.log(`📥 Fetching content of ${path} from ${owner}/${repo}...`);
        
        const response = await axios.get(url, {
            headers: { 
                Authorization: `token ${GITHUB_TOKEN}`,
                Accept: 'application/vnd.github.v3+json'
            }
        });

        const content = Buffer.from(response.data.content, 'base64').toString();

        console.log(`✅ Successfully fetched ${path} (${content.length} characters)`);
        console.log(`📄 ${path} content:\n${content.substring(0, 500)}...`); // Logs first 500 characters

        return content;
    } catch (error) {
        console.error(`❌ Error fetching ${path}:`, error.message);
        throw new Error(`Failed to fetch file content: ${error.message}`);
    }
}


async function processRepo(repoUrl) {
    console.log(`🚀 Processing repository: ${repoUrl}`);
    
    const { owner, repo } = extractRepoDetails(repoUrl);
    console.log(`📂 Repository: ${owner}/${repo}`);
    
    const dependencyFiles = await fetchDependencyFiles(owner, repo);

    if (dependencyFiles.length === 0) {
        console.warn("⚠️ No dependency files available for scanning.");
        return {
            repoUrl,
            owner,
            repo,
            status: "unknown",
            message: "⚠️ No dependency files found."
        };
    }

    const vulnerabilities = [];

    for (const file of dependencyFiles) {
        console.log(`🔍 Scanning ${file.name}...`);
        
        try {
            const fileVulnerabilities = await scanDependencies(file.name, file.content);
            console.log(`🔎 ${file.name} vulnerabilities:`, fileVulnerabilities);
            
            vulnerabilities.push(...fileVulnerabilities.map(v => ({
                ...v,
                file: file.name
            })));
        } catch (err) {
            console.error(`❌ Error scanning ${file.name}:`, err.message);
        }
    }
    
    console.log(`🔒 Total vulnerabilities found: ${vulnerabilities.length}`);

    if (vulnerabilities.length === 0) {
        return {
            repoUrl,
            owner,
            repo,
            status: "secure",
            message: "✅ No vulnerabilities found"
        };
    }

    const fixes = [];

    for (const vulnerability of vulnerabilities) {
        console.log(`🤖 Getting AI suggestion for ${vulnerability.package}@${vulnerability.version}...`);
        
        const suggestion = await suggestFix(vulnerability.package, vulnerability.version);
        
        fixes.push({
            vulnerability,
            suggestion
        });
    }

    return {
        repoUrl,
        owner,
        repo,
        status: "vulnerable",
        vulnerabilities,
        fixes
    };
}

module.exports = {
    processRepo,
    extractRepoDetails,
    fetchDependencyFiles
};
