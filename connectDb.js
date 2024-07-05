const mongoose = require('mongoose');
async function connectDB() {
  try {
    await mongoose.connect(
      'mongodb+srv://abdulsalamasheem:r&c_services@cluster0.38tf9n1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
    );
    console.log('Db connected');
  } catch (err) {
    console.error('db connection failed');
    console.error(err);
  }
}

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

module.exports = connectDB;
