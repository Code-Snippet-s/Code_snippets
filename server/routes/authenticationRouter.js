const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

const authenticationController = require('../controllers/authenticationController');

require('dotenv').config();
const secret = process.env.JWT_SECRET;


// These next 3 routes are not fully operational yet. Out of time on iteration project
router.get('/auth/error', (req, res) => res.send('Unknown Error'));
router.get('/auth/github',passport.authenticate('github',{ scope: [ 'user:email' ] }),(req, res) => {
  console.log('server js auth/github');
});
router.get('/auth/github/callback',passport.authenticate('github', { failureRedirect: '/http://localhost:8080/' }),(req, res) => {
  console.log('Callback hit from auth');
  res.redirect('/authentication/login');
});

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
