const bcrypt = require('bcrypt');

// Replace 'yourAdminPassword' with your desired admin password
const plainPassword = 'liyana1234';
const saltRounds = 15;

bcrypt.hash(plainPassword, saltRounds, function(err, hash) {
  if (err) {
    console.error('Error hashing password:', err);
  } else {
    console.log('Hashed Password:', hash);
  }
});
