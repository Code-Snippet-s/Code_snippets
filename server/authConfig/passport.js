const bcrypt = require('bcrypt');
const passport = require('passport');
const User = require('../models/userModel.js');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const jwtStrategy = require('./jwt.config');
const GitHubStrategy = require('passport-github2').Strategy;


passport.use(jwtStrategy);
passport.use(new LocalStrategy({
  usernameField: 'username', // field name for username in req body
  passwordField: 'password', // field name for password in req body
}, async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    if (!user) {
      // User not found
      return done(null, false, {message: 'Incorrect username or password'});
    }

    // unhash stored password with bcrypt and compare to input password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      // incorrect password
      return done(null, false, {message: 'Incorrect username or password'});
    }

    // Auth successful, return the authenticated user
    return done(null, user);
  } catch (err) {
    // Error occured during the auth process
    return done(`Error occured during the auth process ${err}`);
  }
}
));

// Serialize the user object into a session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize the user object from a session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

/* Out of time to work on this oauth for the iteration
you can confirm that a user will be created or confirmed if you visit 
http://localhost:8080/authentication/auth/github. However it is throwing an error to our global handler 
*/
passport.use(new GitHubStrategy({
  clientID: '27d911b062a8da2de4b9',
  clientSecret: '9bc7e064c2f882d44a6d9a9a1e80a0d37ae0128f',
  callbackURL: 'http://127.0.0.1:3000/authentication/auth/github/callback'
},
async (accessToken, refreshToken, profile, done) => {
  const { username } = profile;
  console.log('Authenticated user profile', profile);
  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      console.log('user already exists');

      return done(null, existingUser);
    }

    // create random password
    const randomPassword = Math.random().toString(36).slice(-8);
    // hash random password
    const hashedPassword = await bcrypt.hash(randomPassword, 10);
    const newUser = await User.create({
      username: profile.username,
      password: hashedPassword
    });
    console.log('new user created');
    return done(null, newUser);
  } catch (err) {
    console.error(`Error occurred during the auth process ${err}`);
    return done(`Error occured during the auth process ${err}`);
  }
}));