const passport = require('passport');
const User = require('../models/userModel.js');

const JwtStrategy = require('passport-jwt').Strategy,
  ExtractJwt = require('passport-jwt').ExtractJwt;

// load env variables
require('dotenv').config();
const secret = process.env.JWT_SECRET;  

// Passport JWT config
const options = {};
// extract JWT from cookie header
options.jwtFromRequest = (req) => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['token'];
  }
  return token;
};
// add our secret
options.secretOrKey = secret;

// new JWT strategy
const jwtStrategy = new JwtStrategy(options,
  async (payload, done) => {
    try{
      // find user based on JWT payload
      const user = await User.findById(payload.userId);
      if (user) {
        // if user is found, return user
        return done(null, user);
      } else {
        // if user is not found, return false
        return done(null, false);
        // or create a new account
      }
    } catch (err) {
      // if error occurs pass to done callback
      return done(err);
    }
  }
);

module.exports = jwtStrategy;