const express = require('express');

const router = express.Router();
const {
  registrationUser, authUser, getLogout, getRefresh,
} = require('../controllers/user');


router.post('/registration', registrationUser);
router.post('/login', authUser);
router.get('/logout', getLogout);
router.get('/refresh', getRefresh);


module.exports = router;