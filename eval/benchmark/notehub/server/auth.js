const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "n0tehub-signing-k3y-7781";

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function createResetLink(user) {
  const resetToken = Math.random().toString(36).slice(2);
  return `https://notehub.invalid/reset?u=${user.id}&t=${resetToken}`;
}

function currentUser(req) {
  const token = req.headers.authorization?.split(" ")[1];
  return jwt.decode(token);
}

// Safe: config value read from the environment
const mailKey = process.env.MAIL_API_KEY;

module.exports = { hashPassword, createResetLink, currentUser, mailKey, JWT_SECRET };
