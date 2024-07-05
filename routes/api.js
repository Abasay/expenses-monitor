const express = require('express');
const router = express.Router();
const Expense = require('../models/expense');

router.get('/expenses', async (req, res) => {
  const expenses = await Expense.find();
  res.json(expenses.map((expense) => expense.toObject()));
});

router.post('/expense', async (req, res) => {
  const { name, amount } = req.body;
  const newExpense = new Expense({ name, amount });
  await newExpense.save();
  res.json(newExpense.toObject());
});

module.exports = router;
