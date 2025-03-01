const request = require("supertest");
const nock = require("nock");
const app = require("./app");

// Function to generate test cases dynamically
async function generateDynamicTestCases(repoUrl) {
  const dependencies = await fetchDependencies(repoUrl); // Get dependency files dynamically

  if (dependencies.length === 0) {
    return {
      repoUrl,
      dependencyFiles: [],
      expectedStatus: 404,
      expectedMessage: "⚠️ No dependency files found in the repository",
      expectedSummary: "unknown",
    };
  }

  const virusTotalResponse = await scanDependencies(dependencies); // Scan them dynamically

  const isMalicious = virusTotalResponse.malicious > 0 || virusTotalResponse.suspicious > 0;

  return {
    repoUrl,
    dependencyFiles: dependencies,
    virusTotalResponse,
    expectedStatus: isMalicious ? 403 : 200,
    expectedMessage: isMalicious
      ? "❌ Malware detected in dependencies!"
      : "✅ Repository scanning complete, including malware detection",
    expectedSummary: isMalicious ? "vulnerable" : "secure",
  };
}

// Function to fetch dependencies dynamically
async function fetchDependencies(repoUrl) {
  try {
    const response = await request(app).post("/fetch-dependencies").send({ repoUrl });
    return response.body.files || [];
  } catch (error) {
    return [];
  }
}

// Function to scan dependencies dynamically
async function scanDependencies(dependencies) {
  try {
    const response = await request(app).post("/scan-malware").send({ dependencies });
    return response.body.analysis || { malicious: 0, suspicious: 0, harmless: 100 };
  } catch (error) {
    return { malicious: 0, suspicious: 0, harmless: 100 };
  }
}

describe("Dynamic Malware Detection & Security Scan Tests", () => {
  let dynamicTestCase;

  beforeAll(async () => {
    const repoUrl = "https://github.com/user/random-repo"; // Can be fetched dynamically
    dynamicTestCase = await generateDynamicTestCases(repoUrl);
  });

  it(`should handle dynamic repository scanning`, async () => {
    nock("https://api.github.com")
      .get(new RegExp(`/repos/.*/contents`))
      .reply(200, dynamicTestCase.dependencyFiles.map(file => ({ name: file.name, path: file.name })));

    if (dynamicTestCase.dependencyFiles.length > 0) {
      nock("https://www.virustotal.com")
        .post("/api/v3/files")
        .reply(200, { data: { attributes: { last_analysis_stats: dynamicTestCase.virusTotalResponse } } });
    }

    const response = await request(app).post("/scan").send({ repoUrl: dynamicTestCase.repoUrl });
 
    expect(response.status).toBe(dynamicTestCase.expectedStatus);
    expect(response.body.message).toContain(dynamicTestCase.expectedMessage);
    if (dynamicTestCase.dependencyFiles.length > 0) {
      expect(response.body.summary.status).toBe(dynamicTestCase.expectedSummary);
    }
  });
});
