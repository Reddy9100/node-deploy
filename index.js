require('dotenv').config();
const express = require("express");
const mysql = require("mysql2");
const app = express();
const bcrypt = require("bcrypt");
const cors = require("cors");

app.use(cors());
app.use(express.json())

const dbconfig = mysql.createConnection({
  host: process.env.Localhost,
  user: process.env.user,
  database: process.env.Database,
  password: process.env.Password
});

app.listen(8000, () => {
  console.log("SERVER IS RUNNING ON PORT HTTP://LOCALHOST:8000");
  dbconfig.connect((err) => {
    if (err) {
      console.log(err);
    } else {
      console.log("Database connection established");
    }
  });
});

app.post("/signup", async (req, res) => {

  const { email, name, password } = req.body;
  console.log(req.body)

  // Check if all required fields are provided
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Fill All Data" });
  }

  try {
    // Check if user with provided email already exists
    const query = "SELECT * FROM users WHERE email = ?";
    dbconfig.query(query, [email], async (err, results) => {
      if (err) {
        console.error("Error checking user existence:", err);
        return res.status(500).json({ message: "Internal Server Error" });
      }

      if (results.length > 0) {
        return res.status(409).json({ message: "User already exists" });
      }
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user into the database
      const insertQuery = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
      dbconfig.query(insertQuery, [name, email, hashedPassword], (err, result) => {
        if (err) {
          console.error("Error creating new user:", err);
          return res.status(500).json({ message: "Internal Server Error" });
        }
        res.status(200).json({ message: "Signup Successful" });
      });
    });
  } catch (error) {
    console.error("Error signing up user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/userdata", async (req, res) => {
  const query = "SELECT * FROM users";
  dbconfig.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    res.status(200).json(results);
  });
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    // Check if user with provided email exists
    const query = "SELECT * FROM users WHERE email = ?";
    dbconfig.query(query, [email], async (err, results) => {
      if (err) {
        console.error("Error checking user existence:", err);
        return res.status(500).json({ message: "Internal Server Error" });
      }
      
      // Check if user exists
      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      // User found, check password
      const user = results[0];
      console.log(user)
      const comparePass = await bcrypt.compare(password, user.password);
      console.log(comparePass)
      if (!comparePass) {
        return res.status(401).json({ message: "Invalid Credentials" });
      }

      return res.status(200).json({ message: "Login Successful", user: { id: user.id, email: user.email } });
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

