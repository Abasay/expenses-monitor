const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const connectDB = require('./connectDb.js');
const path = require('path');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());
// app.use(express.static(path.join(__dirname, 'public')));

connectDB();

// app.use((req, res, next) => {
//   res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
// });

// app.use((err, req, res, next) => {
//   res.status(500).sendFile(path.join(__dirname, 'public', '500.html'));
// });

const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');

// ... other middleware
app.use('/', indexRoutes);
app.use('/auth', authRoutes);
app.use('/api', apiRoutes);

// Database connection
mongoose.connect(
  'mongodb+srv://abdulsalamasheem:r&c_services@cluster0.38tf9n1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
