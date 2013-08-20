
var policy = require('./');

var p = policy({
  secret: 'something',
  length: 5000000,
  bucket: 'i.cloudup.com',
  key: 'asdfasdfaewrw',
  expires: new Date(Date.now() + 60000),
  acl: 'public-read'
});

console.log(p.policy);
console.log(p.signature);