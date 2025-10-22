const http = require("http");
const express = require("express");
const app = express();
const path = require("path");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
require("dotenv").config();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ====== Create HTTP + WebSocket server ======
const server = http.createServer(app);

let wss;
try {
  wss = require("./Websocket")(server);
} catch {
  console.log("Error thrown: Cannot get function from (./Websocket), make sure it is exported correctly!");
}

// ====== Database Connection ======
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) console.log("❌ DB connection error:", err.message);
  else console.log("✅ Connected to MySQL Database");
});

// ====== Email (Nodemailer) Setup ======
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

let otpStore = {}; // Temporary { email: otp }

// ====== Serve your pages ======
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'Home.html')));
app.get('/driver', (req, res) => res.sendFile(path.join(__dirname, 'driver.html')));
app.get('/driverUI', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Serve static files (CSS, JS, etc.)
app.use(express.static(__dirname));


// ====== AUTH ROUTES ======

// --- SIGN UP ---
app.post("/signup", async (req, res) => {
  const { full_name, email, password, phone } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length > 0) return res.status(400).send("User already exists");

    const hashed = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (full_name, email, password, phone) VALUES (?, ?, ?, ?)",
      [full_name, email, hashed, phone],
      err2 => {
        if (err2) return res.status(500).send("Signup failed");
        res.send("Signup successful! You can now log in.");
      }
    );
  });
});

// --- LOGIN (send OTP) ---
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("User not found");

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send("Incorrect password");

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[email] = otp;

    await transporter.sendMail({
      from: `"moveKenya" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Login OTP",
      text: `Your OTP is ${otp}. It expires in 5 minutes.`
    });

    res.send("OTP sent to your email.");
  });
});

// --- VERIFY OTP ---
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (otpStore[email] && otpStore[email] == otp) {
    delete otpStore[email];
    res.send("Login successful!");
  } else {
    res.status(400).send("Invalid OTP");
  }
});

// --- FORGOT PASSWORD ---
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("Email not found");

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[email] = otp;

    await transporter.sendMail({
      from: `"moveKenya" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      text: `Your password reset OTP is ${otp}`
    });

    res.send("Password reset OTP sent.");
  });
});

// --- RESET PASSWORD ---
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (otpStore[email] && otpStore[email] == otp) {
    const hashed = await bcrypt.hash(newPassword, 10);
    db.query("UPDATE users SET password = ? WHERE email = ?", [hashed, email], err => {
      if (err) return res.status(500).send("Error updating password");
      delete otpStore[email];
      res.send("Password reset successful!");
    });
  } else {
    res.status(400).send("Invalid OTP");
  }
});

// ====== SERVER HANDLING ======
process.on("SIGINT", () => {
  if (wss) wss.clients.forEach(client => client.close());
  console.log("SIGINT signal received! Closing server...");
  let seconds = 3;
  const countdown = setInterval(() => {
    console.log(`Closing server in...${seconds}`);
    seconds--;
    if (seconds === 0) {
      clearInterval(countdown);
      server.close();
    }
  }, 1000);
});

server.on("close", () => {
  console.log("Server Closed!");
  process.exit(0);
});

server.listen(3000, () => console.log("🚀 Server running on port 3000..."));
server.on("error", err => console.error("Failed to start Server:", err.message));
