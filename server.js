// server.js
// Vaccination Management System Backend (fixed)
// Node.js + Express + MySQL
// Make sure: npm install express mysql2 jsonwebtoken bcryptjs multer cors dotenv pdfkit

const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- Config ----------
const PORT = Number(process.env.PORT) || 3000;
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = process.env.DB_PORT || 3306;
const DB_USER = process.env.DB_USER || "root";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "dbms";
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

// ---------- Directories ----------
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
const CERT_DIR = path.join(__dirname, "public", "certificates");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// ---------- Multer ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "_" + Math.round(Math.random() * 1e6) + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ---------- MySQL Pool ----------
let pool;
(async function initDb() {
  try {
    pool = await mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      user: DB_USER,
      password: DB_PASS,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
    });
    console.log("Connected to MySQL");
  } catch (err) {
    console.error("MySQL connection error:", err);
    process.exit(1);
  }
})();

// ---------- Helpers ----------
function sendErr(res, err = null, msg = "Server error", code = 500) {
  if (err) console.error("SERVER ERR:", err);
  return res.status(code).json({ success: false, msg });
}
async function query(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows;
}

// ---------- Auth middleware ----------
async function auth(req, res, next) {
  try {
    const h = req.headers["authorization"];
    if (!h || !h.startsWith("Bearer ")) return res.status(401).json({ msg: "No token" });
    const token = h.slice(7);
    const data = jwt.verify(token, JWT_SECRET);
    const rows = await query("SELECT id,name,email,role FROM users WHERE id=?", [data.id]);
    if (!rows || rows.length === 0) return res.status(401).json({ msg: "User not found" });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ msg: "Invalid token" });
  }
}

// ---------- Static ----------
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use("/certificates", express.static(CERT_DIR));

// ======================================================
// AUTH: register & login
// ======================================================
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.json({ success: false, msg: "Missing fields" });

    const exist = await query("SELECT id FROM users WHERE email=?", [email]);
    if (exist.length > 0) return res.json({ success: false, msg: "Email already exists" });

    const hash = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (name,email,password,role) VALUES(?,?,?,?)", [name, email, hash, "patient"]);

        // ⭐ AUTO CREATE PATIENT PROFILE ⭐
    const userRow = await query("SELECT id FROM users WHERE email=?", [email]);
    const newUserId = userRow[0].id;

    await query(
      "INSERT INTO patients (user_id, name) VALUES (?, ?)",
      [newUserId, name]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return sendErr(res, err, "Server error");
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, msg: "Missing" });

    const rows = await query("SELECT * FROM users WHERE email=?", [email]);
    if (!rows.length) return res.json({ success: false, msg: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.json({ success: false, msg: "Invalid credentials" });

        // ⭐ AUTO CREATE PATIENT RECORD IF NOT EXISTS ⭐
    if (user.role === "patient") {
      const pat = await query("SELECT id FROM patients WHERE user_id=?", [user.id]);

      if (pat.length === 0) {
        await query(`
          INSERT INTO patients (user_id, name)
          VALUES (?, ?)
        `, [user.id, user.name]);
      }
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
    return res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return sendErr(res, err, "Server error");
  }
});

// ======================================================
// PATIENT PROFILE
// ======================================================
app.get("/api/patient/profile", auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM patients WHERE user_id=?", [req.user.id]);
    if (rows.length) return res.json(rows[0]);
    return res.json({ id: null, name: req.user.name });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/patient/profile", auth, upload.single("id_proof"), async (req, res) => {
  try {
    const { name, dob, phone, gender, medical_history, address } = req.body;
    const id_proof = req.file ? "/uploads/" + req.file.filename : null;

    const exists = await query("SELECT * FROM patients WHERE user_id=?", [req.user.id]);
    if (exists.length) {
      await query(
        "UPDATE patients SET name=?,dob=?,phone=?,gender=?,medical_history=?,address=?,id_proof=? WHERE user_id=?",
        [name, dob || null, phone || null, gender || null, medical_history || null, address || null, id_proof || exists[0].id_proof, req.user.id]
      );
    } else {
      await query(
        "INSERT INTO patients (user_id,name,dob,phone,gender,medical_history,address,id_proof) VALUES(?,?,?,?,?,?,?,?)",
        [req.user.id, name, dob || null, phone || null, gender || null, medical_history || null, address || null, id_proof]
      );
    }
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

// ======================================================
// VACCINES
// ======================================================
app.get("/api/vaccines", auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM vaccines ORDER BY id DESC");
    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/vaccines", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { name, dose_type, required_age, description, side_effects, manufacturer } = req.body;
    await query("INSERT INTO vaccines (name,dose_type,required_age,description,side_effects,manufacturer) VALUES(?,?,?,?,?,?)", [
      name,
      dose_type || null,
      required_age || 0,
      description || null,
      side_effects || null,
      manufacturer || null,
    ]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.put("/api/vaccines/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { name, dose_type, required_age, description, side_effects, manufacturer } = req.body;
    await query("UPDATE vaccines SET name=?,dose_type=?,required_age=?,description=?,side_effects=?,manufacturer=? WHERE id=?", [
      name,
      dose_type || null,
      required_age || 0,
      description || null,
      side_effects || null,
      manufacturer || null,
      req.params.id,
    ]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.delete("/api/vaccines/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    await query("DELETE FROM vaccines WHERE id=?", [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

// ======================================================
// CENTERS
// ======================================================
app.get("/api/centers", auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM centers ORDER BY id DESC");
    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});

// ⭐ THIS WAS MISSING — ADD THIS ⭐
app.get("/api/centers/:id", auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM centers WHERE id=?", [req.params.id]);
    return res.json(rows[0] || {});
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/centers", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") 
      return res.status(403).json({ success: false, msg: "Unauthorized" });

    const { name, address } = req.body;
    await query("INSERT INTO centers (name,address) VALUES(?,?)", [name, address || null]);
    return res.json({ success: true });

  } catch (err) {
    return sendErr(res, err);
  }
});

app.put("/api/centers/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") 
      return res.status(403).json({ success: false, msg: "Unauthorized" });

    const { name, address } = req.body;
    await query("UPDATE centers SET name=?,address=? WHERE id=?", 
      [name, address || null, req.params.id]
    );
    return res.json({ success: true });

  } catch (err) {
    return sendErr(res, err);
  }
});

app.delete("/api/centers/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") 
      return res.status(403).json({ success: false, msg: "Unauthorized" });

    await query("DELETE FROM centers WHERE id=?", [req.params.id]);
    return res.json({ success: true });

  } catch (err) {
    return sendErr(res, err);
  }
});


// ======================================================
// INVENTORY
// ======================================================
app.get("/api/inventory", auth, async (req, res) => {
  try {
    const rows = await query("SELECT i.*, v.name AS vaccine_name FROM inventory i LEFT JOIN vaccines v ON v.id=i.vaccine_id ORDER BY i.id DESC");
    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});

app.get("/api/inventory/:id", auth, async (req, res) => {
  try {
    const rows = await query("SELECT i.*, v.name AS vaccine_name FROM inventory i LEFT JOIN vaccines v ON v.id=i.vaccine_id WHERE i.id=?", [req.params.id]);
    return res.json(rows[0] || {});
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/inventory", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { vaccine_id, batch_no, quantity, expiry_date } = req.body;
    await query("INSERT INTO inventory (vaccine_id,batch_no,quantity,expiry_date) VALUES(?,?,?,?)", [vaccine_id, batch_no || null, quantity || 0, expiry_date || null]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.put("/api/inventory/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { vaccine_id, batch_no, quantity, expiry_date } = req.body;
    await query("UPDATE inventory SET vaccine_id=?,batch_no=?,quantity=?,expiry_date=? WHERE id=?", [vaccine_id, batch_no || null, quantity || 0, expiry_date || null, req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.delete("/api/inventory/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    await query("DELETE FROM inventory WHERE id=?", [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/inventory/:id/adjust", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { delta } = req.body;
    await query("UPDATE inventory SET quantity = GREATEST(quantity + ?, 0) WHERE id=?", [Number(delta) || 0, req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

// ======================================================
// APPOINTMENTS
// ======================================================
app.get("/api/appointments", auth, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      const rows = await query(`
        SELECT a.*, p.name AS patient_name, v.name AS vaccine_name, c.name AS center_name
        FROM appointments a
        LEFT JOIN patients p ON p.id = a.patient_id
        LEFT JOIN vaccines v ON v.id = a.vaccine_id
        LEFT JOIN centers c ON c.id = a.center_id
        ORDER BY a.appointment_date DESC
      `);
      return res.json(rows);
    } else {
      const pr = await query("SELECT id FROM patients WHERE user_id=?", [req.user.id]);
      const pid = pr[0] ? pr[0].id : null;
      const rows = await query(`
        SELECT a.*, v.name AS vaccine_name, c.name AS center_name
        FROM appointments a
        LEFT JOIN vaccines v ON v.id = a.vaccine_id
        LEFT JOIN centers c ON c.id = a.center_id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_date DESC
      `, [pid]);
      return res.json(rows);
    }
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/appointments", auth, async (req, res) => {
  try {
    if (req.user.role !== "patient") return res.status(403).json({ success: false, msg: "Only patients can book" });
    const { patient_id, vaccine_id, appointment_date, center_id, dose_no, note } = req.body;

     // FIX: ensure valid date from frontend
    let apptDate = new Date(appointment_date);
    if (isNaN(apptDate.getTime())) {
      return res.json({ success: false, msg: "Invalid appointment date format" });
    }

    // ensure patient belongs to user
    const pr = await query("SELECT * FROM patients WHERE id=? AND user_id=?", [patient_id, req.user.id]);
    if (!pr.length) return res.json({ success: false, msg: "Invalid patient record" });

    const inv = await query("SELECT SUM(quantity) AS qty FROM inventory WHERE vaccine_id=? AND (expiry_date IS NULL OR expiry_date >= CURDATE())", [vaccine_id]);
    if (!inv || inv[0].qty <= 0) return res.json({ success: false, msg: "Vaccine out of stock" });

    await query("INSERT INTO appointments (patient_id,vaccine_id,appointment_date,center_id,status,note,dose_no) VALUES(?,?,?,?,?,?,?)", [patient_id, vaccine_id, appointment_date, center_id || null, 'booked', note || null, dose_no || 1]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/appointments/:id/status", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { status } = req.body;
    await query("UPDATE appointments SET status=? WHERE id=?", [status, req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/appointments/:id/assign", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { staff_id } = req.body;
    await query("UPDATE appointments SET assigned_to=? WHERE id=?", [staff_id, req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.post("/api/appointments/:id/complete", auth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });

    const ap = await conn.query("SELECT * FROM appointments WHERE id=?", [req.params.id]);
    if (!ap[0].length) { conn.release(); return res.json({ success: false, msg: "Appointment not found" }); }
    const a = ap[0][0];

    await conn.beginTransaction();

    const doseNo = req.body.dose_no || 1;
    const given_on = new Date();
    const given_by = req.user.id;

    const ins = await conn.query("INSERT INTO vaccination_records (patient_id,vaccine_id,dose_no,given_on,given_by,appointment_id) VALUES(?,?,?,?,?,?)", [a.patient_id, a.vaccine_id, doseNo, given_on, given_by, a.id]);

    // decrement one from earliest non-expired batch
    const [batches] = await conn.query("SELECT * FROM inventory WHERE vaccine_id=? AND (expiry_date IS NULL OR expiry_date >= CURDATE()) AND quantity>0 ORDER BY expiry_date ASC, id ASC", [a.vaccine_id]);
    if (!batches.length) {
      await conn.rollback();
      conn.release();
      return res.json({ success: false, msg: "No inventory available" });
    }
    const batch = batches[0];
    await conn.query("UPDATE inventory SET quantity = quantity - 1 WHERE id=?", [batch.id]);

    await conn.query("UPDATE appointments SET status=? WHERE id=?", ['completed', a.id]);

    await conn.commit();
    conn.release();
    return res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    conn.release();
    return sendErr(res, err);
  }
});

// ======================================================
// VACCINATION RECORDS & CERTIFICATE
// ======================================================
app.get("/api/vaccination-records", auth, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      const rows = await query(`SELECT r.*, p.name as patient_name, v.name as vaccine_name, u.name as staff_name
        FROM vaccination_records r
        LEFT JOIN patients p ON p.id = r.patient_id
        LEFT JOIN vaccines v ON v.id = r.vaccine_id
        LEFT JOIN users u ON u.id = r.given_by
        ORDER BY r.given_on DESC`);
      return res.json(rows);
    } else {
      const pr = await query("SELECT id FROM patients WHERE user_id=?", [req.user.id]);
      const pid = pr[0] ? pr[0].id : null;
      const rows = await query(`SELECT r.*, v.name as vaccine_name, u.name as staff_name
        FROM vaccination_records r
        LEFT JOIN vaccines v ON v.id = r.vaccine_id
        LEFT JOIN users u ON u.id = r.given_by
        WHERE r.patient_id = ?
        ORDER BY r.given_on DESC`, [pid]);
      return res.json(rows);
    }
  } catch (err) {
    return sendErr(res, err);
  }
});

app.put("/api/vaccination-records/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    const { dose_no, given_on } = req.body;
    await query("UPDATE vaccination_records SET dose_no=?, given_on=? WHERE id=?", [dose_no, given_on, req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.delete("/api/vaccination-records/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, msg: "Unauthorized" });
    await query("DELETE FROM vaccination_records WHERE id=?", [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

app.get("/api/vaccination-records/:id/certificate", auth, async (req, res) => {
  try {
    const rows = await query(`SELECT r.*, p.name as patient_name, v.name as vaccine_name, u.name as staff_name
      FROM vaccination_records r
      LEFT JOIN patients p ON p.id = r.patient_id
      LEFT JOIN vaccines v ON v.id = r.vaccine_id
      LEFT JOIN users u ON u.id = r.given_by
      WHERE r.id = ?`, [req.params.id]);
    if (!rows.length) return res.status(404).send("Not found");
    const rec = rows[0];

    const filename = `cert_${req.params.id}.pdf`;
    const filepath = path.join(CERT_DIR, filename);
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(filepath));
    doc.fontSize(18).text("Vaccination Certificate", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Patient: ${rec.patient_name || "—"}`);
    doc.text(`Vaccine: ${rec.vaccine_name || "—"}`);
    doc.text(`Dose No: ${rec.dose_no || "—"}`);
    doc.text(`Given On: ${new Date(rec.given_on).toLocaleString()}`);
    doc.text(`Given By: ${rec.staff_name || "—"}`);
    doc.moveDown();
    doc.text("This certificate is system generated.");
    doc.end();
    doc.on("end", () => {}); // harmless
    // send when file ready (small delay for write)
    setTimeout(() => res.sendFile(filepath), 500);
  } catch (err) {
    return sendErr(res, err);
  }
});

// Get single vaccine by ID (required for edit & patient view)
app.get("/api/vaccines/:id", auth, async (req, res) => {
  try {
    const rows = await query("SELECT * FROM vaccines WHERE id=?", [req.params.id]);
    return res.json(rows[0] || {});
  } catch (err) {
    return sendErr(res, err);
  }
});

// ======================================================
// PATIENT — My Vaccinations
// ======================================================
app.get("/api/my/vaccinations", auth, async (req, res) => {
  try {
    if (req.user.role !== "patient")
      return res.status(403).json({ msg: "Patients only" });

    // get patient record id
    const pr = await query("SELECT id FROM patients WHERE user_id=?", [req.user.id]);
    if (!pr.length) return res.json([]);

    const pid = pr[0].id;

    const rows = await query(`
      SELECT r.*, v.name AS vaccine_name 
      FROM vaccination_records r
      LEFT JOIN vaccines v ON v.id = r.vaccine_id
      WHERE r.patient_id = ?
      ORDER BY r.given_on DESC
    `, [pid]);

    return res.json(rows);

  } catch (err) {
    return sendErr(res, err);
  }
});



// PATIENT → CREATE FEEDBACK
app.post("/api/feedback", auth, upload.single("attachment"), async (req, res) => {
  try {
    const { type, appointment_id, center_id, rating, message } = req.body;

    if (!message || message.trim() === "")
      return res.json({ success: false, msg: "Message required" });

    const attachment = req.file ? "/uploads/" + req.file.filename : null;

    await query(
      `INSERT INTO feedback (user_id, type, appointment_id, center_id, rating, message, attachment_path, status)
       VALUES (?,?,?,?,?,?,?,?)`,
      [
        req.user.id,
        type || "feedback",
        appointment_id || null,
        center_id || null,
        rating || 5,
        message,
        attachment,
        "open"
      ]
    );

    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});


// PATIENT → SEE OWN FEEDBACK
app.get("/api/feedback/my", auth, async (req, res) => {
  try {
    const rows = await query(
      "SELECT * FROM feedback WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );
    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});


// ADMIN → SEE ALL FEEDBACK
app.get("/api/feedback", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Admin only" });

    const rows = await query(`
      SELECT f.*, u.name AS patient_name
      FROM feedback f
      LEFT JOIN users u ON u.id = f.user_id
      ORDER BY f.created_at DESC
    `);

    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});


// ADMIN → SEND REPLY
app.post("/api/feedback/:id/reply", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Admin only" });

    const { reply } = req.body;

    await query(
      "UPDATE feedback SET admin_reply=?, status='open' WHERE id=?",
      [reply || "", req.params.id]
    );

    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});


// ADMIN → CLOSE TICKET
app.post("/api/feedback/:id/close", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Admin only" });

    await query("UPDATE feedback SET status='closed' WHERE id=?", [
      req.params.id,
    ]);

    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});


// ADMIN → DELETE FEEDBACK
app.delete("/api/feedback/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Admin only" });

    await query("DELETE FROM feedback WHERE id=?", [req.params.id]);

    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

// ======================================================
// NOTIFICATIONS SYSTEM (FINAL WORKING VERSION)
// ======================================================

// UNREAD COUNT (PATIENT)
app.get("/api/notifications/unread-count", auth, async (req, res) => {
  try {
    const rows = await query(
      "SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND is_read=0",
      [req.user.id]
    );
    return res.json({ count: rows[0].c });
  } catch (err) {
    return sendErr(res, err);
  }
});

// GET ALL NOTIFICATIONS (PATIENT)
app.get("/api/notifications", auth, async (req, res) => {
  try {
    const rows = await query(
      "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );
    return res.json(rows);
  } catch (err) {
    return sendErr(res, err);
  }
});

// MARK AS READ (PATIENT)
app.post("/api/notifications/read/:id", auth, async (req, res) => {
  try {
    await query(
      "UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
      [req.params.id, req.user.id]
    );
    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});

// ADMIN SEND NOTIFICATION
app.post("/api/admin/notify", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ msg: "Admin only" });

    const { audience, title, message, user_id } = req.body;

    // 1️⃣ SINGLE USER
    if (audience === "single") {
      await query(
        "INSERT INTO notifications (user_id,title,message) VALUES (?,?,?)",
        [user_id, title, message]
      );
      return res.json({ success: true });
    }

    // 2️⃣ ONLY PATIENTS
    if (audience === "patients") {
      const users = await query("SELECT id FROM users WHERE role='patient'");
      for (let u of users) {
        await query(
          "INSERT INTO notifications (user_id,title,message) VALUES (?,?,?)",
          [u.id, title, message]
        );
      }
      return res.json({ success: true });
    }

    // 3️⃣ STAFF
    if (audience === "staff") {
      const users = await query("SELECT id FROM users WHERE role='staff'");
      for (let u of users) {
        await query(
          "INSERT INTO notifications (user_id,title,message) VALUES (?,?,?)",
          [u.id, title, message]
        );
      }
      return res.json({ success: true });
    }

    // 4️⃣ ALL USERS
    const all = await query("SELECT id FROM users");
    for (let u of all) {
      await query(
        "INSERT INTO notifications (user_id,title,message) VALUES (?,?,?)",
        [u.id, title, message]
      );
    }

    return res.json({ success: true });
  } catch (err) {
    return sendErr(res, err);
  }
});


// ======================================================
// START
// ======================================================
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
