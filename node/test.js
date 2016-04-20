const crypto = require('crypto');
const hmac = crypto.createHmac('sha256', 'secret');
hmac.update('Message');
console.log(hmac.digest('hex')); // aa747c502a898200f9e4fa21bac68136f886a0e27aec70ba06daf2e2a5cb5597
