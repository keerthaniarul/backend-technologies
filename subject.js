// ================= IMPORTS =================
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const router = express.Router();

app.use(express.json());
app.use(cors());
// ================= CONFIG =================
const SECRET_KEY = "mySecretKey123";
const PORT = 3000;

// ================= MONGODB CONNECTION =================
mongoose.connect("mongodb://127.0.0.1:27017/kongu")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ================= SCHEMA =================
const personSchema = new mongoose.Schema({
  rollno: { type: Number, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  tamil: { type: Number, required: true },
  english: { type: Number, required: true },
  maths:{type:Number,required:true}
});

// ================= MODEL =================
const Person = mongoose.model("Subjects", personSchema);

// ================= JWT MIDDLEWARE =================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ message: "Authorization header missing" });

  const token = authHeader.split(" ")[1]; // Expecting "Bearer TOKEN"

  if (!token)
    return res.status(401).json({ message: "Token missing" });

  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { rollno, name, password,tamil,english,maths} = req.body;

    // Check if user already exists
    const existingPerson = await Person.findOne({ rollno });
    if (existingPerson) {
      return res.status(400).json({ message: "Roll number already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const person = new Person({
      rollno,
      name,
      password: hashedPassword,
      tamil,
      english,
      maths
    });

    await person.save();
    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try {
    const { rollno, password } = req.body;

    const person = await Person.findOne({ rollno });
    if (!person) return res.status(401).json({ message: "Invalid rollno" });

    const isMatch = await bcrypt.compare(password, person.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ rollno: person.rollno }, SECRET_KEY, { expiresIn: "1h" });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= CRUD ROUTES =================

// Create Person (optional, could use /register instead)
router.post("/", async (req, res) => {
  try {
    const person = new Person(req.body);
    await person.save();
    res.status(201).json(person);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all Persons (PROTECTED)
router.get("/", authMiddleware, async (req, res) => {
  try {
    const persons = await Person.find();
    res.status(200).json(persons);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Person by rollno (PROTECTED)
router.get("/:rollno", authMiddleware, async (req, res) => {
  try {
    const rollno = Number(req.params.rollno);
    const person = await Person.findOne({ rollno });

    if (!person) return res.status(404).json({ message: "Person not found" });

    res.status(200).json(person);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Person by rollno (PROTECTED)
router.put("/:rollno", authMiddleware, async (req, res) => {
  try {
    const rollno = Number(req.params.rollno);

    // If password is being updated, hash it
    if (req.body.password) {
      req.body.password = await bcrypt.hash(req.body.password, 10);
    }

    const updatedPerson = await Person.findOneAndUpdate(
      { rollno },
      req.body,
      { new: true }
    );

    if (!updatedPerson) return res.status(404).json({ message: "Person not found" });

    res.status(200).json({
      message: "Person updated successfully",
      updatedPerson
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete Person by rollno (PROTECTED)
router.delete("/:rollno", authMiddleware, async (req, res) => {
  try {
    const rollno = Number(req.params.rollno);
    const deletedPerson = await Person.findOneAndDelete({ rollno });

    if (!deletedPerson) return res.status(404).json({ message: "Person not found" });

    res.status(200).json({
      message: "Person deleted successfully",
      deletedPerson
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= ROUTER =================
app.use("/person", router);

// ================= SERVER =================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
