const jwt = require('./jwt');
const jwt1 = require('jsonwebtoken');
const secret = 'lsgogroup',
  payload = {
    username: 'zp1996',
    id: 1,
    authority: 32
  };

const token = jwt1.sign(payload, secret);

console.log(jwt.verify(token, secret));
