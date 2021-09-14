const db = require("../users/users-model");
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  req.session.user
    ? next()
    : next({ message: "You shall not pass!", status: 401 });
}

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
    const users = await db.findBy({ username });
    !users.length ? next() : next({ message: "Username taken", status: 422 });
  } catch (err) {
    next(err);
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
    const { username } = req.body;
    const user = await db.findBy({ username });
    user
      ? next(req.user)
      : next({ message: "Invalid credentials", status: 401 });
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
    const pass = req.body.password;
    pass && pass > 3
      ? next()
      : next({ message: "Password must be longer than 3 chars", status: 422 });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
