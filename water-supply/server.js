require('dotenv').config();

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ================= MONGODB =================
const client = new MongoClient(process.env.MONGO_URI);

let users, orders;

async function startServer() {
  try {
    await client.connect();
    console.log("✅ Connected to MongoDB");

    const db = client.db('waterApp');

    users = db.collection('users');
    orders = db.collection('orders');

    app.listen(3000, () => {
      console.log("🚀 Server running on http://localhost:3000");
    });

  } catch (err) {
    console.error("DB ERROR:", err);
  }
}

startServer();


// ================= AUTH =================
function authenticateToken(req, res, next) {

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'secretkey', (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}


// ================= REGISTER =================
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await users.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: "User exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await users.insertOne({ email, password: hashedPassword });

    res.json({ message: "User registered" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Register failed" });
  }
});


// ================= LOGIN =================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await users.findOne({ email });

    if (!user) return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(400).json({ message: "Wrong password" });

    // ✅ ADD ROLE HERE
    const token = jwt.sign(
      { 
        email: user.email,
        role: user.email === "admin@gmail.com" ? "admin" : "user"
      },
      'secretkey'
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ================= CREATE ORDER =================
app.post('/orders', authenticateToken, async (req, res) => {
  try {

    const { name, surname, phone, liters, location } = req.body;

    if (!name || !phone || !liters) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const order = {
      email: req.user.email,
      name,
      surname,
      phone,
      liters,
      location,
      status: "pending",
      createdAt: new Date()
    };

    const result = await orders.insertOne(order);

    res.json(result);

  } catch (err) {
    console.error("ORDER ERROR:", err);
    res.status(500).json({ error: "Order failed" });
  }
});


// ================= GET USER ORDERS =================
// ================= GET ORDERS =================
app.get("/orders", authenticateToken, async (req, res) => {
  try {

    // 👑 ADMIN → GET ALL ORDERS
    if (req.user.role === "admin") {
      const allOrders = await orders.find().toArray();
      return res.json(allOrders);
    }

    // 👤 USER → GET OWN ORDERS ONLY
    const userOrders = await orders
      .find({ email: req.user.email })
      .toArray();

    res.json(userOrders);

  } catch (err) {
    console.error("GET ORDERS ERROR:", err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

// ================= DELETE =================
app.delete('/orders/:id', authenticateToken, async (req, res) => {

  let query = { _id: new ObjectId(req.params.id) };

  // 👤 user can delete only their own
  if (req.user.role !== "admin") {
    query.email = req.user.email;
  }

  await orders.deleteOne(query);

  res.json({ message: "Deleted" });
});


// ================= UPDATE =================
app.put('/orders/:id/status', authenticateToken, async (req, res) => {

  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Not allowed" });
  }

  await orders.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { status: req.body.status } }
  );

  res.json({ message: "Status updated" });
});


// ================= SERVE INDEX =================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// ADD ADMIN CHECK

//const token = jwt.sign(
  //{ //email, role: email === "admin@gmail.com" ? "admin" : "user" },
 // 'secretkey'
//);