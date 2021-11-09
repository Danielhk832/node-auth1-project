const bcrypt = require("bcryptjs");
const User = require("../users/users-model");

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted() {}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body;
    const [user] = await User.findBy({ username });

    if (user) {
      next({ status: 422, message: "Username taken" });
    } else {
      next();
    }
  } catch (error) {
    next(error);
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  try {
    const { username, password } = req.body;
    const [user] = await User.findBy({ username });
    if (!user) {
      return next({ status: 401, message: "Invalid credentials" });
    }
    const doesPasswordCheck = bcrypt.compareSync(password, user.password);
    if (!doesPasswordCheck) {
      return next({ status: 401, message: "Invalid credentials" });
    }

    req.session.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  try {
    if (!req.body.password || req.body.password.length < 3) {
      next({
        status: 422,
        message: "Password must be longer than 3 chars",
      });
    } else {
      next();
    }
  } catch (error) {
    next(error);
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
};
