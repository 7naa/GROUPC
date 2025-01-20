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


// Rate limiter for admin login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: "Too many login attempt,try again later",
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Admin login route with rate limiting
app.post('/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  try {
    const admin = await client.db("user").collection("admin").findOne({ username });

    if (!admin) {
      return res.status(401).send("-");
    }

    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).send("Wrong password! Try again");
    }

    const token = jwt.sign(
      { _id: admin._id, username: admin.username, role: "admin" },
      'hurufasepuluhkali'
    );

    res.send({ _id: admin._id, token, role: "admin" });
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).send("Internal Server Error");
  }
});