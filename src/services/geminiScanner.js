const { GoogleGenerativeAI } = require("@google/generative-ai");
require("dotenv").config();

const API_KEY = process.env.GEMINI_API_KEY;
if (!API_KEY) {
    throw new Error("Missing Gemini API key! Set GEMINI_API_KEY in your .env file.");
}

const genAI = new GoogleGenerativeAI(API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });

/**
 * Scans package.json dependencies for vulnerabilities using Gemini AI.
 * @param {string} packageJsonContent - The contents of package.json as a string.
 * @param {boolean} malwareOnly - If true, only returns malicious packages.
 * @returns {Promise<Object>} - JSON response with vulnerability details.
 */
async function scanWithGemini(packageJsonContent, malwareOnly = false) {
    try {
        if (!packageJsonContent || typeof packageJsonContent !== 'string') {
            throw new Error("Invalid package.json content provided");
        }

        try {
            JSON.parse(packageJsonContent); // Validate JSON
        } catch (parseError) {
            throw new Error("Invalid JSON in package.json content");
        }

        const prompt = `
Analyze the following package.json dependencies for security vulnerabilities.

${malwareOnly ? "Focus specifically on packages with known malware, backdoors, or that have been compromised in the past." : ""}

Your response **MUST** be a valid **JSON object** following this structure:

{
    "fileName": "package.json",
    "summary": "Brief summary of the security risks.",
    "vulnerabilities": {
        "high": [
            { "packageName": "lodash", "version": "4.17.0", "description": "Why it's risky", "recommendation": "What to do", "isMalicious": true/false }
        ],
        "medium": [],
        "low": []
    },
    "recommendations": [
        "General security recommendations"
    ]
}

### IMPORTANT RULES:
- 🚨 **DO NOT** include explanations, additional text, or Markdown formatting (like \`\`\`json).
- 🚨 **DO NOT** include anything outside the JSON object.
- 🚨 Ensure **valid** JSON syntax with no missing commas or extra brackets.
- 🚨 If there are no vulnerabilities, return \`"vulnerabilities": { "high": [], "medium": [], "low": [] }\`.
- 🚨 If a package has been **previously compromised**, set \`"isMalicious": true\`.

Here is the package.json file content:
${packageJsonContent}
        `;

        console.log("🔍 Sending request to Gemini API...");
        const result = await model.generateContent(prompt);
        const responseText = result.response.text();
        console.log("✅ Received response from Gemini API");

        // Strip markdown code blocks if present
        let cleanResponse = responseText.trim();
        if (responseText.startsWith("```") && responseText.endsWith("```")) {
            cleanResponse = responseText.replace(/^```(json)?/, '').replace(/```$/, '').trim();
        }

        try {
            const parsedResponse = JSON.parse(cleanResponse);

            // If malwareOnly is true, filter only malicious packages
            if (malwareOnly) {
                const filteredResponse = {
                    fileName: parsedResponse.fileName,
                    summary: "Malicious packages that require immediate attention",
                    vulnerabilities: {
                        high: parsedResponse.vulnerabilities.high.filter(v => 
                            v.isMalicious === true || 
                            v.description.toLowerCase().includes("malicious") ||
                            v.description.toLowerCase().includes("backdoor") ||
                            v.description.toLowerCase().includes("compromised") ||
                            ["event-stream", "flatmap-stream"].includes(v.packageName) // Known compromised packages
                        ),
                        medium: [],
                        low: []
                    },
                    recommendations: [
                        "Remove all malicious packages immediately",
                        "Scan your system for potential backdoors",
                        "Reset any secrets that might have been compromised"
                    ]
                };
                return filteredResponse;
            }

            return parsedResponse;
        } catch (jsonError) {
            console.error("❌ Failed to parse Gemini response as JSON:", jsonError);
            console.error("🔍 Raw response:", responseText);
            throw new Error("Gemini didn't return valid JSON. See logs for details.");
        }
    } catch (error) {
        console.error("⚠️ Gemini API Error:", error);
        return {
            fileName: "package.json",
            error: error.message || "Error occurred during scanning."
        };
    }
}

/**
 * Extracts and returns only the malicious packages.
 * @param {string} packageJsonContent - The contents of package.json as a string.
 * @returns {Promise<Object>} - Malicious packages and recommendations.
 */
async function getMaliciousPackages(packageJsonContent) {
    const result = await scanWithGemini(packageJsonContent, true);

    return {
        maliciousPackages: result.vulnerabilities.high.map(pkg => pkg.packageName),
        recommendations: result.vulnerabilities.high.map(pkg => 
            `${pkg.packageName}@${pkg.version}: ${pkg.recommendation}`
        )
    };
}

// Example usage
async function example() {
    const packageJson = `{
        "name": "test-project",
        "dependencies": {
            "express": "4.0.0",
            "lodash": "4.17.0",
            "event-stream": "3.3.6",
            "flatmap-stream": "0.1.1"
        }
    }`;
    
    const malicious = await getMaliciousPackages(packageJson);
    console.log("\n🚨 Malicious packages to remove:", malicious.maliciousPackages);
    console.log("\n🔧 Recommendations:");
    malicious.recommendations.forEach(rec => console.log("- " + rec));
}

// Run example when executed directly
if (require.main === module) {
    example();
}

module.exports = { scanWithGemini, getMaliciousPackages };
