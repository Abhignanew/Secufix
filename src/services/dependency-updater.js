const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const simpleGit = require("simple-git");

// Configuration (Can be loaded from a JSON file or environment variables)
const config = {
  scanRecursive: true,
  backupFiles: true,
  logLevel: "info", // "info", "warn", "error", "debug"
  autoFix: true,
  gitCommit: true,
  gitPush: true,
  commitMessage: "chore: update dependencies to secure versions"
};

// Secure versions mapping (Replace with API calls in production)
const secureVersions = {
  // JavaScript/Node.js
  "express": "4.18.2",
  "lodash": "4.17.21",
  "axios": "1.6.2",
  "react": "18.2.0",
  "next": "14.0.3",
  // Python
  "Flask": "2.2.3",
  "requests": "2.31.0",
  "django": "4.2.7",
  "numpy": "1.26.1",
  // Java
  "org.springframework": "5.3.30",
  "com.fasterxml.jackson.core": "2.15.3",
  "org.apache.logging.log4j": "2.20.0"
};

// Logger function
const logger = {
  debug: (msg) => config.logLevel === "debug" && console.log(`🔍 DEBUG: ${msg}`),
  info: (msg) => ["info", "debug"].includes(config.logLevel) && console.log(`ℹ️ ${msg}`),
  warn: (msg) => ["info", "debug", "warn"].includes(config.logLevel) && console.log(`⚠️ ${msg}`),
  error: (msg) => console.error(`❌ ERROR: ${msg}`),
  success: (msg) => console.log(`✅ ${msg}`)
};

// Create backup of a file
function createBackup(filePath) {
  return;
  if (!config.backupFiles) return;
  const backupPath = `${filePath}.backup-${Date.now()}`;
  fs.copyFileSync(filePath, backupPath);
  logger.debug(`Created backup: ${backupPath}`);
}

// Function to update `package.json` (JavaScript/Node.js)
async function updatePackageJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      logger.warn(`File not found: ${filePath}`);
      return { file: filePath, status: "skipped", reason: "not found" };
    }

    createBackup(filePath);
    let packageJson = JSON.parse(fs.readFileSync(filePath, "utf8"));
    let updatedCount = 0;
    let updates = [];

    for (const depType of ["dependencies", "devDependencies"]) {
      if (!packageJson[depType]) continue;

      Object.keys(packageJson[depType]).forEach(dep => {
        if (secureVersions[dep]) {
          const currentVersion = packageJson[depType][dep];
          if (currentVersion.includes(secureVersions[dep])) return;

          // Preserve version prefix (^, ~)
          const versionMatch = currentVersion.match(/^([~^])/);
          const prefix = versionMatch ? versionMatch[1] : "";

          packageJson[depType][dep] = `${prefix}${secureVersions[dep]}`;
          updatedCount++;
          updates.push({ package: dep, from: currentVersion, to: `${prefix}${secureVersions[dep]}` });
        }
      });
    }

    if (updatedCount > 0 && config.autoFix) {
      fs.writeFileSync(filePath, JSON.stringify(packageJson, null, 2));
      logger.success(`Updated ${updatedCount} dependencies in ${filePath}`);
    }

    return { file: filePath, status: updatedCount > 0 ? "updated" : "no_changes", updates };
  } catch (error) {
    logger.error(`Failed to update ${filePath}: ${error.message}`);
    return { file: filePath, status: "error", error: error.message };
  }
}

// Function to update `requirements.txt` (Python)
async function updateRequirementsTxt(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      logger.warn(`File not found: ${filePath}`);
      return { file: filePath, status: "skipped", reason: "not found" };
    }

    createBackup(filePath);
    let lines = fs.readFileSync(filePath, "utf8").split("\n");
    let updatedCount = 0;

    const newLines = lines.map(line => {
      if (!line.trim() || line.startsWith("#")) return line;
      const [pkg, version] = line.split("==");
      if (secureVersions[pkg]) {
        updatedCount++;
        return `${pkg}==${secureVersions[pkg]}`;
      }
      return line;
    });

    if (updatedCount > 0 && config.autoFix) {
      fs.writeFileSync(filePath, newLines.join("\n"));
      logger.success(`Updated ${updatedCount} dependencies in ${filePath}`);
    }

    return { file: filePath, status: updatedCount > 0 ? "updated" : "no_changes" };
  } catch (error) {
    logger.error(`Failed to update ${filePath}: ${error.message}`);
    return { file: filePath, status: "error", error: error.message };
  }
}

// Function to update `pom.xml` (Java/Maven)
async function updatePomXml(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      logger.warn(`File not found: ${filePath}`);
      return { file: filePath, status: "skipped", reason: "not found" };
    }

    createBackup(filePath);
    let pomXml = fs.readFileSync(filePath, "utf-8");

    Object.keys(secureVersions).forEach(dep => {
      const regex = new RegExp(`(<artifactId>${dep}</artifactId>\\s*<version>)([^<]+)(</version>)`, "g");
      pomXml = pomXml.replace(regex, `$1${secureVersions[dep]}$3`);
    });

    fs.writeFileSync(filePath, pomXml);
    logger.success(`Updated dependencies in ${filePath}`);

    return { file: filePath, status: "updated" };
  } catch (error) {
    logger.error(`Failed to update ${filePath}: ${error.message}`);
    return { file: filePath, status: "error", error: error.message };
  }
}

// Function to push changes to GitHub
async function pushToGit() {
  try {
    const git = simpleGit();
    await git.add(".");
    await git.commit(config.commitMessage);
    await git.push("origin", "main");
    logger.success("✅ Changes pushed to GitHub!");
  } catch (error) {
    logger.error(`❌ Failed to push changes to GitHub: ${error.message}`);
  }
}

// Main function
async function main() {
  try {
    logger.info("🚀 Starting Dynamic Dependency Updater");

    const files = ["./package.json", "./requirements.txt", "./pom.xml"];
    let results = [];

    for (const file of files) {
      if (file.endsWith("package.json")) results.push(await updatePackageJson(file));
      if (file.endsWith("requirements.txt")) results.push(await updateRequirementsTxt(file));
      if (file.endsWith("pom.xml")) results.push(await updatePomXml(file));
    }

    if (config.gitCommit && config.gitPush) {
      await pushToGit();
    }

    logger.success("🎉 Dependency update process completed!");
  } catch (error) {
    logger.error(`Main process failed: ${error.message}`);
  }
}

// Run the script
main();
