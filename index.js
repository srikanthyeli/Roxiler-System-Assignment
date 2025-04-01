const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();
const databasePath = path.join(__dirname, "covid19India.db");

const app = express();
app.use(express.json());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    await createTables();
    app.listen(3001, () =>
      console.log("Server Running at http://localhost:3001/")
    );
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

const createTables = async () => {
  await database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      address TEXT NOT NULL,
      role TEXT CHECK(role IN ('Admin', 'User', 'StoreOwner')) NOT NULL
    );
  `);
  
  await database.exec(`
    CREATE TABLE IF NOT EXISTS stores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      address TEXT NOT NULL
    );
  `);
  
  await database.exec(`
    CREATE TABLE IF NOT EXISTS ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      store_id INTEGER,
      rating INTEGER CHECK(rating BETWEEN 1 AND 5),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE
    );
  `);
};

const generateToken = (user) => {
  return jwt.sign({ id: user.id, role: user.role },  "My_Secrete_Token" ,{ expiresIn: "1h" });
};

app.post("/register", async (req, res) => {
  const { name, email, password, address, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await database.run(
      "INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashedPassword, address, role]
    );
    res.status(201).send("User Registered Successfully");
  } catch (err) {
    res.status(400).send({ error: "User registration failed" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await database.get("SELECT * FROM users WHERE email = ?", [email]);
  console.log(user)
  if (!user) {
    return res.status(400).send("Invalid user");
  }
  
  const isPasswordMatch = await bcrypt.compare(password, user.password);
  if (!isPasswordMatch) {
    return res.status(400).send("Invalid password");
  }
  
  const token = generateToken(user);
  res.send({ token });
});

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).send("Access Denied");
    
    try {
      const verified = jwt.verify(token,  "My_Secrete_Token");
      console.log(verified)
      if (roles.length && !roles.includes(verified.role)) {
        return res.status(403).send("Unauthorized");
      }
      req.user = verified;
      next();
    } catch {
      res.status(400).send("Invalid Token");
    }
  };
};



app.get("/users", authMiddleware(["Admin"]), async (req, res) => {
  const users = await database.all("SELECT id, name, email, address, role FROM users");
  res.send(users);
});
app.get("/stores", authMiddleware(["StoreOwner", "Admin"]), async (req, res) => {
  const stores = await database.all("SELECT * FROM stores");
  res.send(stores);
});

app.post("/stores", authMiddleware(["Admin"]), async (req, res) => {
  const { name, email, address } = req.body;
  try {
    await database.run("INSERT INTO stores (name, email, address) VALUES (?, ?, ?)", [name, email, address]);
    res.status(201).send("Store Added Successfully");
  } catch (err) {
    res.status(400).send({ error: "Store creation failed" });
  }
});

app.get("/admin/stats", authMiddleware(["Admin"]), async (req, res) => {
    try {
      const usersCount = await database.get("SELECT COUNT(*) as count FROM users");
      const storesCount = await database.get("SELECT COUNT(*) as count FROM stores");
      const ratingsCount = await database.get("SELECT COUNT(*) as count FROM ratings");
      res.send({ users: usersCount.count, stores: storesCount.count, ratings: ratingsCount.count });
    } catch (err) {
      res.status(500).send({ error: "Failed to fetch stats" });
    }
  });

  app.get("/admin/users", authMiddleware(["Admin"]), async (req, res) => {
    try {
      const users = await database.all("SELECT * FROM users");
      res.send(users);
    } catch (err) {
      res.status(500).send({ error: "Failed to fetch users" });
    }
  });

  app.get("/stores/search", authMiddleware(["User", "Admin"]), async (req, res) => {
    const { query } = req.query;
    console.log(query)
    const stores = await database.all(
      "SELECT * FROM stores WHERE name LIKE ? OR address LIKE ?",
      [`%${query}%`, `%${query}%`]
    );
    res.send(stores);
  });
  
  app.post("/ratings", authMiddleware(["User"]), async (req, res) => {
    const { store_id, rating } = req.body;
    try {
      await database.run(
        "INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)",
        [req.user.id, store_id, rating]
      );
      res.status(201).send("Rating Submitted Successfully");
    } catch (err) {
      res.status(400).send({ error: "Failed to submit rating" });
    }
  });
  
  app.put("/ratings", authMiddleware(["User"]), async (req, res) => {
    const { store_id, rating } = req.body;
    try {
      await database.run(
        "UPDATE ratings SET rating = ? WHERE user_id = ? AND store_id = ?",
        [rating, req.user.id, store_id]
      );
      res.status(200).send("Rating Updated Successfully");
    } catch (err) {
      res.status(400).send({ error: "Failed to update rating" });
    }
  });
  
  app.get("/store/ratings", authMiddleware(["StoreOwner"]), async (req, res) => {
    const storeId = req.user.id;
    const ratings = await database.all(
      `SELECT users.id, users.name, users.email, ratings.rating 
       FROM ratings 
       JOIN users ON ratings.user_id = users.id 
       WHERE ratings.store_id = ?`, 
      [storeId]
    );
    res.send(ratings);
  });
  
  app.get("/store/average-rating", authMiddleware(["StoreOwner"]), async (req, res) => {
    const storeId = req.user.id;
    const avgRating = await database.get(
      "SELECT AVG(rating) AS average FROM ratings WHERE store_id = ?",
      [storeId]
    );
    res.send(avgRating);
  });

initializeDbAndServer();

