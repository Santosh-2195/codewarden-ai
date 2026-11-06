const express = require("express");
const { exec } = require("child_process");
const db = require("../db");

const router = express.Router();

// Search notes by title
router.get("/api/notes/search", async (req, res) => {
  try {
    const rows = await db.query("SELECT id, title FROM notes WHERE title LIKE '%" + req.query.q + "%'");
    res.json(rows.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fetch a single note (parameterised, but no ownership check)
router.get("/api/notes/:id", async (req, res) => {
  const note = await db.query("SELECT * FROM notes WHERE id = $1", [req.params.id]);
  res.json(note.rows[0]);
});

// Safe: parameterised and scoped to the logged-in user
router.get("/api/my-notes", requireAuth, async (req, res) => {
  const notes = await db.query("SELECT * FROM notes WHERE owner_id = $1", [req.user.id]);
  res.json(notes.rows);
});

// Export a note as an image
router.post("/api/notes/export", (req, res) => {
  exec(`convert ${req.body.file} /tmp/out.png`, (error) => {
    if (error) return res.status(500).send("export failed");
    res.sendFile("/tmp/out.png");
  });
});

router.get("/login/callback", (req, res) => {
  res.redirect(req.query.next);
});

function requireAuth(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}

module.exports = router;
