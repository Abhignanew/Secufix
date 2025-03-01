const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { processRepo } = require("./services/githubService");

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.post("/scan", async (req, res) => {
    const { repoUrl } = req.body;
    
    if (!repoUrl) {
        return res.status(400).json({ 
            error: "❌ GitHub URL is required" 
        });
    }

    try {
        // Process the repository
        const result = await processRepo(repoUrl);
        
        // Return success response
        res.json({ 
            message: "✅ Processing started", 
            result 
        });
    } catch (error) {
        console.error("Error processing repository:", error);
        
        // Return error response
        res.status(500).json({ 
            error: "❌ Failed to process repo", 
            details: error.message 
        });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({ status: "healthy" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});

module.exports = app; // For testing