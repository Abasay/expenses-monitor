const express = require('express');
const router = express.Router();
const Expense = require('../models/expense.js');
const auth = require('../protect.js');

// Get all expenses

router.use(auth);
router.get('/expenses', async (req, res) => {
  try {
    const expenses = await Expense.find();
    res.json(expenses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add new expense
router.post('/expenses', async (req, res) => {
  const { name, amount } = req.body;
  try {
    const newExpense = new Expense({ name, amount });
    await newExpense.save();
    res.status(201).json(newExpense);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update an expense
router.put('/expenses/:id', async (req, res) => {
  const { id } = req.params;
  const { name, amount } = req.body;
  try {
    const updatedExpense = await Expense.findByIdAndUpdate(
      id,
      { name, amount },
      { new: true }
    );
    res.json(updatedExpense);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete an expense
router.delete('/expenses/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await Expense.findByIdAndDelete(id);
    res.status(204).end();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
