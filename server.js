// server.js
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const User = require("./models/User");

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "87654321";
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

console.log("🔄 Starting authentication server...");

const app = express();

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs for auth endpoints
  message: {
    error: "Too many authentication attempts, please try again later."
  },
  skipSuccessfulRequests: true // Don't count successful logins
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // Limit each IP to 100 requests per windowMs
});

// Middleware
app.use(cors({
  origin: [
    'https://sande-family.vercel.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],
  credentials: true
}));
app.use(express.json({ limit: "10mb" }));
app.use(generalLimiter);

// MongoDB connection
console.log("🔄 Connecting to MongoDB...");
mongoose.connect("mongodb+srv://danmarksande:38327090@cluster0.1598eg2.mongodb.net/auth_system?retryWrites=true&w=majority&appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Input validation middleware
const validateSignup = (req, res, next) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  if (name.length < 2) {
    return res.status(400).json({ error: "Name must be at least 2 characters long" });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }
  
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  
  next();
};

const validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  
  next();
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = req.cookies?.token || (authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader);
    
    if (!token) {
      return res.status(401).json({ error: "Access token required" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("❌ Token verification failed:", error.message);
    
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    }
    
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    
    res.status(500).json({ error: "Authentication failed" });
  }
};

// ------------------ AUTHENTICATION ROUTES ------------------

// Health check route
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "OK", 
    service: "Authentication API",
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Test route
app.get("/", (req, res) => {
  res.json({ 
    message: "🔐 Authentication API is running",
    version: "1.0.0",
    timestamp: new Date().toISOString()
  });
});

// Signup route
app.post("/signup", authLimiter, validateSignup, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({ error: "User with this email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const newUser = new User({ 
      name: name.trim(), 
      email: email.toLowerCase().trim(), 
      password: hashedPassword 
    });
    
    await newUser.save();

    // Generate token
    const token = jwt.sign(
      { id: newUser._id }, 
      JWT_SECRET, 
      { expiresIn: "7d" } // Longer expiry for better UX
    );

    // Set HTTP-only cookie for additional security
    res.cookie("token", token, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(201).json({ 
      success: true,
      message: "Account created successfully!",
      token, // Also send in response for mobile apps
      user: { 
        id: newUser._id, 
        name: newUser.name, 
        email: newUser.email,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    console.error("❌ Signup error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to create account. Please try again." 
    });
  }
});

// Login route
app.post("/login", authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("🔐 Login attempt for:", email);

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      console.log("❌ Login failed: User not found");
      return res.status(401).json({ 
        success: false,
        error: "Invalid email or password" 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log("🔑 Password match:", isMatch);

    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: "Invalid email or password" 
      });
    }

    const token = jwt.sign(
      { id: user._id }, 
      JWT_SECRET, 
      { expiresIn: "7d" }
    );

    // Set HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    console.log("✅ Login successful for:", email);
    
    res.json({ 
      success: true,
      message: "Login successful!",
      token,
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        createdAt: user.createdAt
      } 
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ 
      success: false,
      error: "Login failed. Please try again." 
    });
  }
});

// Logout route
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ 
    success: true,
    message: "Logged out successfully" 
  });
});

// Check authentication status
app.get("/auth/check", authenticateToken, (req, res) => {
  res.json({ 
    success: true,
    authenticated: true,
    user: req.user 
  });
});

// Protected Route - User Profile
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      user: req.user,
      message: "Profile retrieved successfully"
    });
  } catch (error) {
    console.error("❌ Profile fetch error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to fetch profile" 
    });
  }
});

// Update user profile
app.put("/profile", authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name || name.length < 2) {
      return res.status(400).json({ 
        success: false,
        error: "Name must be at least 2 characters long" 
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { name: name.trim() },
      { new: true }
    ).select("-password");

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser
    });
  } catch (error) {
    console.error("❌ Profile update error:", error);
    res.status(500).json({ 
      success: false,
      error: "Failed to update profile" 
    });
  }
});

// 404 handler - FIXED: Use proper route pattern
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    error: "Route not found" 
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("🚨 Unhandled error:", error);
  res.status(500).json({ 
    success: false,
    error: "Internal server error" 
  });
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("🔄 Shutting down gracefully...");
  await mongoose.connection.close();
  console.log("✅ MongoDB connection closed");
  process.exit(0);
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Authentication server running on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${NODE_ENV}`);
  console.log(`🔐 Endpoints:`);
  console.log(`   POST /signup - User registration`);
  console.log(`   POST /login - User login`);
  console.log(`   POST /logout - User logout`);
  console.log(`   GET /profile - Get user profile`);
  console.log(`   GET /auth/check - Check authentication status`);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (err) => {
  console.error("🚨 Unhandled Promise Rejection:", err);
  server.close(() => {
    process.exit(1);
  });
});

module.exports = app;