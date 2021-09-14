const router = require("express").Router();
const User = require("../users/users-model");
const bcrypt = require("bcryptjs");
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("./auth-middleware");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hash = bcrypt.hashSync(password, 8); // 2 ^ 8
      const newUser = { username, password: hash };
      const user = await User.add(newUser);

      res.status(201).json(user);
    } catch (error) {
      next(error);
    }
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
// router.post("/login", checkUsernameExists, async (req, res, next) => {
//   try {
//     const { username, password } = req.body;
//     //const [existingUser] = await User.findBy({ username });
//     // check if username in db
//     // recreate hash from password
//     // if username exists, AND hash matches the one in db
//     // THEN START A SESSION WITH THE HELP OF A LIB expresse-session
//     const existingUser = req.user;
//     if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
//       // here this means user exists AND credentials good
//       console.log("starting session!!!");
//       req.session.user = existingUser;
//       res.json({
//         message: `welcome back, ${existingUser.username}`,
//       });
//     } else {
//       next({ status: 401, message: "bad credentials!" });
//     }
//   } catch (err) {
//     next(err);
//   }
// });
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [existingUser] = await User.findBy({ username });
    if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
      req.session.user = existingUser;
      res.status(200).json({
        message: `Welcome ${existingUser.username}`,
      });
    } else {
      next({
        message: "Invalid credentials",
        status: 401,
      });
    }
  } catch (err) {
    next(err);
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get("/logout", async (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) => {
        if (err) {
          res.json({
            message: "err, you cannot leave",
          });
        } else {
          res.json({
            message: "logged out",
          });
        }
      });
    } else {
      res.json({
        message: "no session",
      });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
