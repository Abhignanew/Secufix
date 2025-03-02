#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { scanWithGemini, getMaliciousPackages } = require('../src/services/geminiScanner');

// Parse command line arguments
const args = process.argv.slice(2);
const saveFlag = args.includes('--save');
let targetPackage = args.find(arg => !arg.startsWith('--'));

async function scanPackages() {
  try {
    console.log('🔍 Scanning packages for security vulnerabilities...');

    // Get package.json path - either from argument or current directory
    let packageJsonPath;
    
    if (targetPackage) {
      // Check if it's a direct path to package.json
      if (targetPackage.endsWith('package.json')) {
        packageJsonPath = path.resolve(process.cwd(), targetPackage);
      } else {
        // Assume it's a package name and check node_modules
        packageJsonPath = path.resolve(process.cwd(), 'node_modules', targetPackage, 'package.json');
      }
    } else {
      // Default to current directory's package.json
      packageJsonPath = path.resolve(process.cwd(), 'package.json');
    }

    // Ensure package.json exists
    if (!fs.existsSync(packageJsonPath)) {
      console.error(`❌ Error: package.json not found at ${packageJsonPath}`);
      console.error(`Usage: package-scan [package-name or path/to/package.json] [--save]`);
      process.exit(1);
    }

    // Read the package.json file
    const packageJsonContent = await fs.promises.readFile(packageJsonPath, 'utf8');
    
    // Get package name for reporting
    let packageName;
    try {
      packageName = JSON.parse(packageJsonContent).name || path.basename(path.dirname(packageJsonPath));
    } catch (e) {
      packageName = path.basename(path.dirname(packageJsonPath));
    }
    
    console.log(`📦 Scanning package: ${packageName}`);

    // Scan for vulnerabilities
    const fullScanResult = await scanWithGemini(packageJsonContent);

    // Save full scan results to a file if --save flag is used
    if (saveFlag) {
      const resultFilename = `${packageName}-scan-results.json`;
      await fs.promises.writeFile(
        path.resolve(process.cwd(), resultFilename),
        JSON.stringify(fullScanResult, null, 2)
      );
      console.log(`Results saved to ${resultFilename}`);
    }

    // Check for malicious packages
    const maliciousResult = await getMaliciousPackages(packageJsonContent);

    // Display summary of issues
    console.log('\n📊 Vulnerability Summary:');
    const highCount = fullScanResult.vulnerabilities?.high?.length || 0;
    const mediumCount = fullScanResult.vulnerabilities?.medium?.length || 0;
    const lowCount = fullScanResult.vulnerabilities?.low?.length || 0;
    
    console.log(`🔴 High: ${highCount}`);
    console.log(`🟠 Medium: ${mediumCount}`);
    console.log(`🟡 Low: ${lowCount}`);

    // Display detailed results in console
    if (highCount > 0) {
      console.log('\n🔴 High Severity Vulnerabilities:');
      fullScanResult.vulnerabilities.high.forEach(vuln => {
        console.log(`- ${vuln.packageName}@${vuln.version}${vuln.isMalicious ? ' (MALICIOUS)' : ''}`);
        console.log(`  ${vuln.description}`);
        console.log(`  Recommendation: ${vuln.recommendation}`);
      });
    }

    if (maliciousResult.maliciousPackages.length > 0) {
      console.log('\n⚠️ WARNING: POTENTIALLY MALICIOUS PACKAGES DETECTED ⚠️');
      maliciousResult.maliciousPackages.forEach(pkg => console.log(`- ${pkg}`));
      console.log('\nRecommendations:');
      maliciousResult.recommendations.forEach(rec => console.log(`- ${rec}`));
      
      if (saveFlag) {
        console.log(`\nDetailed scan results saved to ${packageName}-scan-results.json`);
      }

      process.exit(1); // Exit with error code if malicious packages found
    } else {
      console.log('✅ No malicious packages detected.');
      
      if (saveFlag) {
        console.log(`Detailed scan results saved to ${packageName}-scan-results.json`);
      } else if (highCount > 0 || mediumCount > 0) {
        console.log(`Use --save flag to save detailed scan results to a file`);
      }
    }
  } catch (error) {
    console.error('❌ Error scanning packages:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

scanPackages();