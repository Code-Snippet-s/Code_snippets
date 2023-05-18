const passport = require('../authConfig/passport.js');
const User = require('../models/userModel.js');
const bcrypt = require('bcrypt');
const authenticationController = {};

authenticationController.signUp = async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return next({
        log: 'Error occured in authenticationController.signUp',
        status: 400,
        message: 'Username already exists, please select another',
      });
    }

    // password encryption
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      username: req.body.username,
      password: hashedPassword,
    });
    res.locals.newUser = newUser;
    return next();
  } catch (err) {
    return next(err);
  }
};

module.exports = authenticationController;
