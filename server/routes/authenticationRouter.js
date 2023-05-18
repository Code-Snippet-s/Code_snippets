const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

const authenticationController = require('../controllers/authenticationController');

require('dotenv').config();
const secret = process.env.JWT_SECRET;

router.post('/signup', authenticationController.signUp, (req, res) => {
  return res.status(201).json({ username: res.locals.newUser.username });
});

router.post('/login',
  passport.authenticate('local', { session: false }),
  (req, res) => {
    console.log(req.user);
    const token = jwt.sign({ userId: req.user.id }, secret, {
      expiresIn: '1d',
    });
    res.cookie('token', token, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // Expires in 30 days
      httpOnly: true,
    });
    res.cookie('userId', req.user.id, {
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // Expires in 30 days
      httpOnly: true,
    });
    return res.status(202).json({ username: req.user.username });
  }
);

router.get(
  '/protected',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    console.log('at protected router, SUCCESS!');
    res.send('Protected route accessed!');
  }
);

module.exports = router;
