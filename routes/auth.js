const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user.js');
const path = require('path');

router.get('/signup', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../public/signup.html'));
});

router.get('/login', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../public/login.html'));
});

router.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.redirect('/auth/login');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id },
      'SHA256:2OX+gLfwrfWwcAOdJwz+c/CZad/gkwQ7+HKTjGyM7bAabdul@DESKTOP-TKPHVCI',
      {
        expiresIn: '1h',
      }
    );
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/');
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
