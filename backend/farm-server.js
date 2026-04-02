const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const { authenticator } = require('otplib');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
app.use(express.json());

const mongoURI = process.env.MONGODB_URI;

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  twoFactorSecret: { type: String },
});

const User = mongoose.model('User', userSchema);

app.post('/register', [
  body('username').isString().notEmpty(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, twoFactorSecret: authenticator.generateSecret() });
  await user.save();
  res.status(201).json({ message: 'User registered successfully.' });
});

app.post('/login', async (req, res) => {
  const { username, password, token } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Authentication failed.' });

  const isVerified = authenticator.check(token, user.twoFactorSecret);
  if (!isVerified) return res.status(401).json({ message: 'Invalid token.' });

  const accessToken = jwt.sign({ username: user.username }, process.env.JWT_SECRET);
  res.json({ accessToken });
});

app.post('/send-email', async (req, res) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const { to, subject, text } = req.body;
  const info = await transporter.sendMail({ from: process.env.EMAIL, to, subject, text });
  res.json({ message: 'Email sent', info });
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});

app.use(limiter);

const farmAssets = [];

app.post('/add-asset', (req, res) => {
  const asset = req.body;
  farmAssets.push(asset);
  res.json({ message: 'Asset added.', assets: farmAssets });
});

// Additional endpoints for vehicles, security lights, perimeter walls, and greenhouses...

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
