const axios = require("axios");
require("dotenv").config();

const API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_URL = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateText";

/**
 * Scans JavaScript code for potential malware using Gemini AI.
 * @param {string} code - JavaScript code to analyze.
 * @returns {Promise<string>} - AI-generated security assessment.
 */
async function scanWithGemini(code) {
    if (!API_KEY) {
        throw new Error("Gemini API Key is missing!");
    }

    try {
        const response = await axios.post(
            `${GEMINI_URL}?key=${API_KEY}`,
            {
                prompt: `Analyze the following JavaScript code for potential malware, security risks, and vulnerabilities: \n\n${code}`,
                temperature: 0.7,
                max_tokens: 500,
            }
        );

        return response.data.candidates[0].output || "No issues detected.";
    } catch (error) {
        console.error("Error scanning with Gemini:", error.message);
        return "Error occurred during scanning.";
    }
}

module.exports = { scanWithGemini };
