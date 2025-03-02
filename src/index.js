const { program } = require("commander");
const dotenv = require("dotenv");
const axios = require("axios");
const githubService = require("./services/githubService");
const secureDependencyService = require("./services/secureDependencies");
const { scanDependencies } = require("./services/securityScanner");
const { scanWithGemini } = require("./services/geminiScanner");
const fs = require("fs");
const FormData = require("form-data");

// Load environment variables
dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

// Ensure API keys are set
// if (!VIRUSTOTAL_API_KEY) {
//   console.error("❌ Missing VirusTotal API key! Set VIRUSTOTAL_API_KEY in your .env file.");
//   process.exit(1);
// }
if (!GEMINI_API_KEY) {
  console.error("❌ Missing Gemini API key! Set GEMINI_API_KEY in your .env file.");
  process.exit(1);
}

/**
 * Function: Scan for malware using VirusTotal API
 */
const scanForMalware = async (filePath) => {
  try {
    const fileStream = fs.createReadStream(filePath);
    const form = new FormData();
    form.append("file", fileStream);

    const response = await axios.post("https://www.virustotal.com/api/v3/files", form, {
      headers: {
        "x-apikey": VIRUSTOTAL_API_KEY,
        ...form.getHeaders(),
      },
    });

    return response.data;
  } catch (error) {
    console.error("❌ Malware scan failed:", error.response?.data || error.message);
    return null;
  }
};

/**
 * Main function: Scan repository, detect malware, and fix vulnerabilities
 */
const scanRepository = async (repoUrl) => {
  if (!repoUrl) {
    console.error("❌ GitHub URL is required");
    process.exit(1);
  }

  try {
    console.log(`🚀 Processing repository: ${repoUrl}`);
    const { owner, repo } = githubService.extractRepoDetails(repoUrl);
    console.log(`📂 Repository: ${owner}/${repo}`);

    // Fetch dependency files
    const dependencyFiles = await githubService.fetchDependencyFiles(owner, repo);
    if (dependencyFiles.length === 0) {
      console.warn("⚠️ No dependency files found in the repository");
      return;
    }

    for (const file of dependencyFiles) {
      console.log(`🔍 Processing ${file.name}...`);

      // Write content to a temporary file for scanning
      const tempFilePath = `./temp_${file.name}`;
      fs.writeFileSync(tempFilePath, file.content);

      // 1. Malware Detection
      console.log(`🛡️ Scanning ${file.name} for malware...`);
      const malwareResult = await scanForMalware(tempFilePath);
      fs.unlinkSync(tempFilePath); // Delete temp file after scanning

      if (malwareResult && malwareResult.data.attributes.last_analysis_stats.malicious > 0) {
        console.error("❌ Malware detected in dependencies!");
        process.exit(1);
      }

      // 2. AI-based Code Analysis
      console.log(`🤖 AI Analysis for ${file.name}...`);
      const aiAnalysis = await scanWithGemini(file.content);
      console.log(`🔍 AI Report:\n${JSON.stringify(aiAnalysis, null, 2)}`);

      // 3. Scan for vulnerabilities
      const vulnerabilities = await scanDependencies(file.name, file.content);
      console.log(`🔎 Found ${vulnerabilities.length} vulnerabilities in ${file.name}`);

      // 4. Secure Dependencies
      if (vulnerabilities.length > 0) {
        console.log(`🔒 Fetching secure dependencies for ${file.name}...`);
        const secureVersions = await secureDependencyService.fetchSecureDependencies(file.name, file.content);
        console.log("✅ Suggested Secure Versions:", secureVersions);
      }
    }

    console.log("✅ Repository scanning complete!");
  } catch (error) {
    console.error("❌ Error processing repository:", error.message);
    process.exit(1);
  }
};

// Setup CLI commands
program
  .version("1.0.0")
  .description("CLI tool to scan GitHub repositories for vulnerabilities and malware")
  .argument("<repoUrl>", "GitHub repository URL")
  .action(scanRepository);

program.parse(process.argv);
