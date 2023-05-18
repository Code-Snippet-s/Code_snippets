const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const cookieParser = require('cookie-parser');

const snippetsRouter = require('./routes/snippetsRouter');
const authenticationRouter = require('./routes/authenticationRouter');


require('dotenv').config();

//Create express app and set constants
const app = express();
const port = process.env.PORT || 3000;

//Get mongoURI and connect to DB
const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI);

// initialize passport
app.use(passport.initialize());
// initialize session

// parse incoming cookies and store them on req.cookies object
app.use(cookieParser());
// allow cookies to be included in CORS request
app.use(cors({
  origin: 'http://localhost:8080',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/snippets', snippetsRouter);
app.use('/authentication', authenticationRouter);

//Handle requests to invalid endpoints and middleware errors
app.use((req, res) => res.status(404).send('Invalid endpoint'));
app.use((err, req, res, next) => {
  const defaultErr = {
    log: 'Express error handler caught unknown middleware error',
    status: 500,
    message: { err: 'An error occurred' }
  };
  const errorObj = Object.assign({}, defaultErr, err);
  console.log(errorObj);
  return res.status(errorObj.status).json(errorObj.message);
});

//Get 'er goin'
app.listen(port, () => {
  console.log(`Server listening on port ${port}...`);
});
