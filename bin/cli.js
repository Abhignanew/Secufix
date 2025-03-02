#!/usr/bin/env node

const axios = require('axios');
const { program } = require('commander');
const ora = require('ora');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Configure CLI
program
  .name('repo-scan')
  .description('Scan GitHub repositories for vulnerable dependencies')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a GitHub repository')
  .requiredOption('--repo <url>', 'GitHub repository URL')
  .option('--api <url>', 'API URL', 'http://localhost:3000')
  .action(async (options) => {
    const spinner = ora('Scanning repository...').start();
    
    try {
      const response = await axios.post(`${options.api}/scan`, {
        repoUrl: options.repo
      });
      
      spinner.succeed('Scan completed');
      
      const result = response.data.result;
      
      console.log('\n=== Scan Results ===');
      console.log(`Repository: ${result.owner}/${result.repo}`);
      console.log(`Status: ${result.status === 'secure' ? '✅ Secure' : '❌ Vulnerable'}`);
      
      if (result.status === 'secure') {
        console.log(result.message);
      } else {
        console.log(`\nVulnerabilities Found (${result.vulnerabilities.length}):\n`);
        
        result.vulnerabilities.forEach((vuln, index) => {
          console.log(`[${index + 1}] ${vuln.package}@${vuln.version} - ${vuln.severity.toUpperCase()}`);
          console.log(`    Title: ${vuln.title}`);
          console.log(`    Description: ${vuln.description}`);
          
          if (result.fixes && result.fixes[index]) {
            console.log('\n    AI Suggested Fix:');
            if (result.fixes[index].suggestion.recommendedVersion) {
              console.log(`    Recommended Version: ${result.fixes[index].suggestion.recommendedVersion}`);
            }
            if (result.fixes[index].suggestion.alternativePackage) {
              console.log(`    Alternative Package: ${result.fixes[index].suggestion.alternativePackage}`);
            }
            if (result.fixes[index].suggestion.explanation) {
              console.log(`    Explanation: ${result.fixes[index].suggestion.explanation}`);
            }
          }
          
          console.log(); // Empty line between vulnerabilities
        });
        
        if (result.prUrl) {
          console.log(`\nA pull request with fixes has been created: ${result.prUrl}`);
        }
      }
    } catch (error) {
      spinner.fail('Scan failed');
      
      if (error.response) {
        console.error(`Error: ${error.response.data.error || 'Unknown error'}`);
        if (error.response.data.details) {
          console.error(`Details: ${error.response.data.details}`);
        }
      } else {
        console.error(`Error: ${error.message}`);
      }
      
      process.exit(1);
    }
  });

program.parse();