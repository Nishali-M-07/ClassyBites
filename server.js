require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  verified: { type: Boolean, default: false },
  verificationToken: String
});

const User = mongoose.model('User', userSchema);

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Signup Endpoint
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create verification token
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Save user to DB
    const newUser = new User({
      email,
      password: hashedPassword,
      verificationToken
    });
    await newUser.save();

    // Send verification email
    await transporter.sendMail({
      from: 'Classy Bites <noreply@classybites.com>',
      to: email,
      subject: 'Verify Your Account',
      html: `<p>Click this link to verify your account:<br>
            <a href="http://localhost:3000/verify/${verificationToken}">Verify Account</a></p>`
    });

    res.status(201).json({ message: "Verification email sent" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Verification Endpoint
app.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.status(400).send('Invalid token');

    user.verified = true;
    user.verificationToken = null;
    await user.save();

    res.send('Account verified successfully!');
  } catch (error) {
    res.status(400).send('Invalid or expired token');
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) return res.status(400).json({ message: "User not found" });
    if (!user.verified) return res.status(400).json({ message: "Account not verified" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));