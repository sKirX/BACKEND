require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // JWT
const app = express();
const SECRET_KEY = process.env.JWT_SECRET;

app.use(express.json());

// MySQL Pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});
// POST /auth/register
app.post('/auth/register', async (req, res) => {
  try {
    const { fullname, address, phone, email, username, password } = req.body;

    // ตรวจสอบว่ากรอกครบไหม
    if (!fullname || !address || !phone || !email || !username || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // ตรวจสอบว่า username ซ้ำหรือไม่
    const [existing] = await db.query(
      "SELECT * FROM tbl_customers WHERE username = ?",
      [username]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Hash password ด้วย bcryptjs
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert ลง database
    const [result] = await db.query(
      `INSERT INTO tbl_customers 
      (fullname, address, phone, email, username, password)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [fullname, address, phone, email, username, hashedPassword]
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId
    });

  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const [rows] = await db.query(
      "SELECT * FROM tbl_customers WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

const verifyToken = require('./middleware/auth');

// ตัวอย่าง API ที่ต้องการตรวจสอบ Token
app.get('/profile', verifyToken, async (req, res) => {
  try {
    // req.user จะมีข้อมูลจาก token
    res.json({ message: "Welcome!", user: req.user });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});
// GET /customers - ต้องมี token
app.get('/customers', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, username, fullname, lastname, email, phone FROM tbl_customers");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// สมมติว่ามี db เป็น mysql2/promise pool และ verifyToken เป็น middleware ตรวจสอบ token
app.post('/orders', verifyToken, async (req, res) => {
  try {
    const { menu_id, quantity } = req.body;

    if (!menu_id || !quantity) {
      return res.status(400).json({ error: "Missing menu_id or quantity" });
    }

    // ดึงข้อมูลเมนูพร้อมราคาจาก tbl_menus และ restaurant_id
    const [menuRows] = await db.query(
      "SELECT id, restaurant_id, price FROM tbl_menus WHERE id = ?",
      [menu_id]
    );

    if (menuRows.length === 0) {
      return res.status(404).json({ error: "Menu not found" });
    }

    const menu = menuRows[0];
    const total_price = menu.price * quantity;

    // ดึง customer_id จาก token (req.user.id)
    const customer_id = req.user.id;
    const restaurant_id = menu.restaurant_id;

    // บันทึกคำสั่งซื้อ
    const [result] = await db.query(
      `INSERT INTO tbl_orders
       (customer_id, restaurant_id, menu_id, quantity, price, total, order_status)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [customer_id, restaurant_id, menu_id, quantity, menu.price, total_price, "Processing"]
    );

    res.status(201).json({
      message: "Order placed successfully",
      orderId: result.insertId,
      total_price
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// GET /orders/summary - ต้องใช้ token
app.get('/orders/summary', verifyToken, async (req, res) => {
  try {
    const customer_id = req.user.id; // ดึง customer_id จาก token

    const query = `
      SELECT c.fullname AS customer_name, SUM(o.total) AS total_amount
      FROM tbl_orders o
      JOIN tbl_customers c ON o.customer_id = c.id
      JOIN tbl_menus m ON o.menu_id = m.id
      WHERE o.customer_id = ?
      GROUP BY c.id
    `;

    const [rows] = await db.query(query, [customer_id]);

    if (rows.length === 0) {
      return res.json({ customer_name: "", total_amount: 0 });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get('/menus', verifyToken, async (req, res) => {
  try {
    const query = `
      SELECT 
        m.id AS menu_id,
        m.menu_name,
        m.description,
        m.price,
        m.category,
        r.id AS restaurant_id,
        r.restaurant_name,
        r.address AS restaurant_address,
        r.phone AS restaurant_phone,
        r.menu_description
      FROM tbl_menus m
      JOIN tbl_restaurants r ON m.restaurant_id = r.id
    `;
    
    const [rows] = await db.query(query);
    res.json(rows);
    
  } catch (err) {
    console.error("Menus API Error:", err);
    res.status(500).json({ error: err.message });
  }
});



// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
