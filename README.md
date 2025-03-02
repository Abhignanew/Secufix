---
# SecuFix - Automated Dependency Updater & Security Scanner  

SecuFix is a CLI tool that automatically updates project dependencies to secure versions, scans JavaScript files for vulnerabilities using Gemini AI, and integrates with GitHub for version control.  

## 🚀 Features  

- **Dependency Updates**: Supports JavaScript (`package.json`), Python (`requirements.txt`), and Java (`pom.xml`).  
- **Automated Security Scanning**: Uses Gemini AI to analyze JavaScript files.  
- **Backup Mechanism**: Creates backups before modifying files.  
- **GitHub Integration**: Automatically commits and pushes secure updates.  
- **Custom Logging System**: Supports multiple log levels (`info`, `warn`, `error`, `debug`).
- **Security checking in local changes**: before pushing

## 📦 Installation  

Clone the repository and install dependencies:  

```sh
git clone https://github.com/Abhignanew/Secufix.git
cd Secufix
npm install
```

## 🔧 Configuration  

Modify `config` in `index.js`:  

```js
const config = {
  scanRecursive: true,
  backupFiles: true,
  logLevel: "info", // "info", "warn", "error", "debug"
  autoFix: true,
  gitCommit: true,
  gitPush: true,
  commitMessage: "chore: update dependencies to secure versions"
};
```

## 🛠 Usage  

### Start the CLI  

To start the SecuFix CLI and scan a GitHub repository for outdated dependencies and vulnerabilities, run:  

```sh
node src/index.js "GITHUB_REPO_URL"
```

Replace `"GITHUB_REPO_URL"` with the actual repository URL. SecuFix will:  

1. Clone the repository.  
2. Analyze its dependencies.  
3. Identify and update vulnerable versions.  
4. Push secure updates to GitHub (if configured).  

### Scan Local Changes  

To scan a specific package for vulnerabilities in your local project, use:  

```sh
node bin/localScanner.js lodash
```

Replace `lodash` with any package name to analyze its security risks in your project.  

### Update Dependencies  

Run the script to scan and update dependencies in your local project:  

```sh
node index.js
```

### Scan Project for Vulnerabilities  

To analyze JavaScript files in a project directory using Gemini AI:  

```sh
node scan.js /path/to/project
```

## 🔄 How It Works  

1. **Fetches dependencies from `package.json`, `requirements.txt`, and `pom.xml`.**  
2. **Compares versions with a secure version list.**  
3. **Updates dependencies and creates a backup.**  
4. **Scans JavaScript files for vulnerabilities.**  
5. **Commits and pushes changes to GitHub.**  

## ✅ Supported Languages & Files  

| Language  | Supported Files  |  
|-----------|-----------------|  
| JavaScript | `package.json`, `.js` files |  
| Python | `requirements.txt` |  
| Java | `pom.xml` |  

## 🛡 Security Scanner  

The `scan.js` script recursively scans all `.js` files in a directory and uses Gemini AI to analyze them.  

Example usage:  

```sh
node scan.js /path/to/project
```
---
