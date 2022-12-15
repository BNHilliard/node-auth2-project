const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const jwt = require('jsonwebtoken') 

router.post("/register", validateRoleName, (req, res, next) => {
  req.body.username = req.body.username.trim()
  let {username, password} = req.body;
  const {role_name} = req;  
  const hash = bcrypt.hashSync(password, 8)
  password = hash;

  Users.add({username, password: hash, role_name }) 
  .then(resp => {
    res.status(201).json(resp)
  }).catch(err => {
    next(err)
  })
   
  
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }
    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", (req, res, next) => {
  let {username, password} = req.body
  Users.findBy({username})
  .then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)){
    const token = generateJwt(user)
    res.status(200).json({message: `${username} is back!`, token})
    } else {
      res.status(401).json({message: 'Invalid Credentials'})
    }
  }).catch(err => {
    next(err)
  })

  function generateJwt(user) {
    const payload = { 
      subject: user.user_id, 
      role: user.role_name, 
      username: user.username,
    }; 
  
     const config = { expiresIn: '1d'};
  
    return jwt.sign(payload, JWT_SECRET, config);
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});



module.exports = router;
