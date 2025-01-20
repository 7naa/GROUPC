const express = require('express');
const rateLimit = require('express-rate-limit');
const app = express();
const port = process.env.PORT || 4000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// Middleware to parse JSON in request body
app.use(express.json());

const uri = "mongodb+srv://7naa:hurufasepuluhkali@cluster0.4oeznz2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Rate limiting middleware for login routes
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: {
    status: 429,
    error: "Too many login attempts from this IP, please try again after 15 minutes."
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Function to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    if (err) return res.sendStatus(403);

    req.identity = decoded; // Attach decoded user data to the request
    next();
  });
}

// Middleware to verify admin role
function verifyAdmin(req, res, next) {
  if (req.identity.role !== 'admin') {
    return res.status(403).send('Forbidden: Admins only.');
  }
  next();
}

// Admin login
app.post('/admin/login', loginRateLimiter, async (req, res) => {
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

// User login
app.post('/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing username or password");
  }

  try {
    const user = await client.db("user").collection("userdetail").findOne({ username });

    if (!user) {
      return res.status(401).send("-");
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send("Wrong password! Try again");
    }

    const token = jwt.sign(
      { _id: user._id, username: user.username, name: user.name, role: "user" },
      'hurufasepuluhkali'
    );

    res.send({ _id: user._id, token, role: "user" });
  } catch (error) {
    console.error("Error during user login:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// MongoDB connection setup
async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB successfully!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}
run().catch(console.dir);
