// server.js
const http = require("http");
const express = require("express");
const app = express();
const path = require("path");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
require("dotenv").config();

// ===== Middleware =====
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ===== Create HTTP + WebSocket server =====
const server = http.createServer(app);
let wss;
try {
  const wsModule = require("./Websocket");
  if (typeof wsModule === "function") {
    wss = wsModule(server);
    console.log("✅ WebSocket server initialized successfully!");
  } else {
    console.log("❌ WebSocket module does not export a function.");
  }
} catch (err) {
  console.error("❌ Failed to initialize WebSocket:", err.message);
}

// ===== Database Connection =====
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

// ===== Nodemailer Setup =====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

let otpStore = {}; // { email: { otp, role } }

// ====== ROUTES ======

// ----- Serve HTML Pages -----
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "auth.html")));
app.get("/otp", (req, res) => res.sendFile(path.join(__dirname, "otp.html")));
app.get("/user-dashboard", (req, res) => res.sendFile(path.join(__dirname, "user-dashboard.html")));
app.get("/admin/dashboard", (req, res) => res.sendFile(path.join(__dirname, "admin-dashboard.html")));
app.get("/driver", (req, res) => res.sendFile(path.join(__dirname, "driver.html")));
app.get("/driverUI", (req, res) => res.sendFile(path.join(__dirname, "index.html"))); // optional

// ----- Serve static files (CSS/JS/Images in same folder) -----
app.use(express.static(__dirname));

// ====== AUTH ROUTES ======

// SIGNUP (user only)
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

// LOGIN (all roles)
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const tables = ["admins", "users", "drivers"];

  const checkNext = (index) => {
    if (index >= tables.length) return res.status(404).send("Account not found");

    const table = tables[index];
    db.query(`SELECT * FROM ${table} WHERE email = ?`, [email], async (err, result) => {
      if (err) return res.status(500).send("Database error");
      if (result.length === 0) return checkNext(index + 1);

      const user = result[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).send("Incorrect password");

      let role = table === "admins" ? "admin" : table === "drivers" ? "driver" : "user";
      const otp = Math.floor(100000 + Math.random() * 900000);
      otpStore[email] = { otp, role };

      await transporter.sendMail({
        from: `"moveKenya" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Your Login OTP",
        text: `Your OTP is ${otp}. It expires in 5 minutes.`
      });

      res.send("OTP sent to your email");
    });
  };

  checkNext(0);
});

// VERIFY OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const entry = otpStore[email];

  if (entry && entry.otp == otp) {
    const role = entry.role;
    delete otpStore[email];
    res.json({ message: "Login successful!", role });
  } else {
    res.status(400).send("Invalid OTP");
  }
});

// FORGOT PASSWORD
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).send("Database error");
    if (result.length === 0) return res.status(404).send("Email not found");

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[email] = { otp };

    await transporter.sendMail({
      from: `"moveKenya" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      text: `Your password reset OTP is ${otp}`
    });

    res.send("Password reset OTP sent.");
  });
});

// RESET PASSWORD
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const entry = otpStore[email];

  if (entry && entry.otp == otp) {
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

// ADD DRIVER
// ===== ADD DRIVER =====
app.post("/admin/add-driver", async (req, res) => {
  const { full_name, email, phone, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO drivers (full_name, email, phone, password, status) VALUES (?, ?, ?, ?, 'inactive')",
    [full_name, email, phone, hashed],
    err => {
      if (err) return res.status(500).send("Failed to add driver");
      res.send("Driver added successfully");
    }
  );
});



// ===== ADMIN DASHBOARD API =====
app.get("/admin/drivers", (req, res) => {
  db.query("SELECT * FROM drivers", (err, result) => {
    if (err) return res.status(500).send("DB error");
    res.json(result);
  });
});

app.put("/admin/driver-status/:id", (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  db.query("UPDATE drivers SET status = ? WHERE driver_id = ?", [status, id], err => {
    if (err) return res.status(500).send("DB error");
    res.send("Status updated");
  });
});

app.delete("/admin/driver/:id", (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM drivers WHERE driver_id = ?", [id], err => {
    if (err) return res.status(500).send("DB error");
    res.send("Driver deleted");
  });
});

// ====== Server handling ======
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
