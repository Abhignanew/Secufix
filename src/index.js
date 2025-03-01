const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const axios = require("axios");
const githubService = require("./services/githubService");
const secureDependencyService = require("./services/secureDependencies");
const { scanDependencies } = require("./services/securityScanner");
const { scanWithGemini } = require("./services/geminiScanner");

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

/**
 * Function: Scan for malware using VirusTotal API
 */
const scanForMalware = async (fileContent) => {
  try {
    const response = await axios.post("https://www.virustotal.com/api/v3/files", fileContent, {
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      },
    });
    return response.data;
  } catch (error) {
    console.error("❌ Malware scan failed:", error);
    return null;
  }
};

/**
 * Endpoint: Scan Repository, Detect Malware, and Fix Vulnerabilities
 */
app.post("/scan", async (req, res) => {
  const { repoUrl } = req.body;
  if (!repoUrl) {
    return res.status(400).json({ error: "❌ GitHub URL is required" });
  }

  try {
    console.log(`🚀 Processing repository: ${repoUrl}`);
    const { owner, repo } = githubService.extractRepoDetails(repoUrl);
    console.log(`📂 Repository: ${owner}/${repo}`);
    
    // Fetch dependency files
    const dependencyFiles = await githubService.fetchDependencyFiles(owner, repo);
    if (dependencyFiles.length === 0) {
      return res.status(404).json({
        status: "warning",
        message: "⚠️ No dependency files found in the repository",
        repoUrl,
        owner,
        repo,
      });
    }
    
    // Process all dependency files
    const results = [];
    for (const file of dependencyFiles) {
      console.log(`🔍 Processing ${file.name}...`);

      // 1. Malware Detection using VirusTotal
      console.log(`🛡️ Scanning ${file.name} for malware...`);
      const malwareResult = await scanForMalware(file.content);
      if (malwareResult && malwareResult.data.attributes.last_analysis_stats.malicious > 0) {
        return res.status(403).json({
          error: "❌ Malware detected in dependencies!",
          details: malwareResult.data.attributes.last_analysis_stats,
        });
      }

      // 2. AI-based Code Analysis using Gemini
      console.log(`🤖 AI Analysis for ${file.name}...`);
      const aiAnalysis = await scanWithGemini(file.content);
      console.log(`🔍 AI Report:\n${aiAnalysis}`);

      // 3. Scan for vulnerabilities
      const vulnerabilities = await scanDependencies(file.name, file.content);
      console.log(`🔎 Found ${vulnerabilities.length} vulnerabilities in ${file.name}`);

      // 4. Only fetch secure versions if vulnerabilities were found
      let secureVersions = [];
      let updatedContent = null;
      
      if (vulnerabilities.length > 0) {
        console.log(`🔒 Fetching secure dependencies for ${file.name}...`);
        secureVersions = await secureDependencyService.fetchSecureDependencies(file.name, file.content);
        updatedContent = secureDependencyService.generateSecureFile(file.name, file.content, secureVersions);
      }
      
      // 5. Add to results
      results.push({
        fileName: file.name,
        aiAnalysis,
        vulnerabilities,
        secureVersions,
        updatedContent,
        summary: {
          totalVulnerabilities: vulnerabilities.length,
          totalDependencies: secureVersions.length,
          needsUpdate: secureVersions.filter(dep => !dep.isSecure).length,
        },
      });
    }
    
    // Return combined results
    res.status(200).json({
      status: "success",
      message: "✅ Repository scanning complete, including AI-based malware detection",
      repoUrl,
      owner,
      repo,
      results,
      summary: {
        totalFiles: dependencyFiles.length,
        totalVulnerabilities: results.reduce((sum, r) => sum + r.vulnerabilities.length, 0),
        status: results.some(r => r.vulnerabilities.length > 0) ? "vulnerable" : "secure",
      },
    });
  } catch (error) {
    console.error("❌ Error processing repository:", error);
    res.status(500).json({
      error: "❌ Failed to scan and fix repository",
      details: error.message,
    });
  }
});

/**
 * Endpoint: Health Check
 */
app.get("/health", (req, res) => {
  res.json({ status: "healthy" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

module.exports = app;
