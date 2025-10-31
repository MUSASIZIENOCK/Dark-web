/**
 * server.js
 *
 * Single-file demo server:
 * - Express server serving a minimal frontend
 * - Stripe Checkout integration (use STRIPE_SECRET and STRIPE_WEBHOOK_SECRET for real Stripe)
 * - Fallback mock payment if no Stripe keys provided (so you can run locally without Stripe)
 * - SQLite (better-sqlite3) for persistence
 * - Socket.io for private messages; client encrypts messages before sending
 *
 * IMPORTANT: This is a demo starter. Hardening, HTTPS, production config, KYC, and proper secret management are required.
 */

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");

const STRIPE_SECRET = process.env.STRIPE_SECRET || ""; // set if you want real Stripe
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const PUBLIC_URL = process.env.PUBLIC_URL || "http://localhost:3000"; // used for Stripe success/cancel redirects
const JWT_SECRET = process.env.JWT_SECRET || "replace_this_with_a_strong_secret";
const PORT = parseInt(process.env.PORT || "3000", 10);

const stripe = STRIPE_SECRET ? new Stripe(STRIPE_SECRET, { apiVersion: "2024-11-01" }) : null;

// --- DB init ---
const db = new Database(path.join(__dirname, "app.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  is_active INTEGER DEFAULT 0,
  public_key TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  provider TEXT,
  provider_ref TEXT,
  amount INTEGER,
  currency TEXT,
  status TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  user_a TEXT,
  user_b TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  conv_id TEXT,
  sender_id TEXT,
  ciphertext TEXT,
  nonce TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
`);

// prepared stmts
const insertUser = db.prepare("INSERT OR IGNORE INTO users (id, email, public_key, is_active) VALUES (?, ?, ?, ?)");
const getUserByEmail = db.prepare("SELECT * FROM users WHERE email = ?");
const getUserById = db.prepare("SELECT * FROM users WHERE id = ?");
const activateUserByEmail = db.prepare("UPDATE users SET is_active = 1 WHERE email = ?");
const upsertPayment = db.prepare("INSERT OR REPLACE INTO payments (id, user_id, provider, provider_ref, amount, currency, status) VALUES (?, ?, ?, ?, ?, ?, ?)");
const createConversation = db.prepare("INSERT OR IGNORE INTO conversations (id, user_a, user_b) VALUES (?, ?, ?)");
const getConversation = db.prepare("SELECT * FROM conversations WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)");
const insertMessage = db.prepare("INSERT INTO messages (id, conv_id, sender_id, ciphertext, nonce) VALUES (?, ?, ?, ?, ?)");

// helpers
const { v4: uuidv4 } = require("uuid");

/* Utility: create JWT */
function createJwt(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function verifyJwt(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// Express app
const app = express();
app.use(helmet());
app.use(bodyParser.json({ verify: (req, res, buf) => {
  // keep raw body for webhook verification (Stripe)
  req.rawBody = buf;
}}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// --- API: basic status ---
app.get("/api/ping", (req, res) => res.json({ ok: true }));

// --- API: create "checkout" for signup ---
// If STRIPE_SECRET set, create a Stripe Checkout session.
// If not set, return a mock payment URL which triggers immediate activation.
app.post("/api/create-checkout", async (req, res) => {
  const email = (req.body.email || "").toLowerCase();
  if (!email) return res.status(400).json({ error: "email required" });

  // ensure user record exists (inactive until payment confirmed)
  const id = uuidv4();
  insertUser.run(id, email, null, 0);

  const amountCents = 10000; // $100.00
  const currency = "usd";

  if (stripe) {
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        line_items: [{
          price_data: {
            currency,
            product_data: { name: "Membership - one-time" },
            unit_amount: amountCents
          },
          quantity: 1
        }],
        customer_email: email,
        success_url: `${PUBLIC_URL}/?checkout_success=1`,
        cancel_url: `${PUBLIC_URL}/?checkout_cancel=1`
      });
      // store a payment with provider_ref = session.id, status = 'pending'
      upsertPayment.run(uuidv4(), id, "stripe", session.id, amountCents, currency, "pending");
      return res.json({ url: session.url });
    } catch (err) {
      console.error("Stripe create session error:", err);
      return res.status(500).json({ error: "stripe error" });
    }
  } else {
    // Mock flow: create local "payment link" that will call a local endpoint to simulate webhook success
    const mockRef = uuidv4();
    upsertPayment.run(uuidv4(), id, "mock", mockRef, amountCents, currency, "pending");
    const mockUrl = `${PUBLIC_URL}/mock-pay?ref=${mockRef}&email=${encodeURIComponent(email)}`;
    return res.json({ url: mockUrl });
  }
});

// --- Mock pay page trigger (only for local demo) ---
app.get("/mock-pay", (req, res) => {
  // mark payment as succeeded and activate user
  const ref = req.query.ref;
  const email = req.query.email;
  if (!ref || !email) return res.status(400).send("missing");
  // find user by email and activate
  activateUserByEmail.run(email);
  // update payment status (best-effort)
  const p = db.prepare("UPDATE payments SET status = 'paid' WHERE provider_ref = ?").run(ref);
  res.send(`<h2>Mock payment successful for ${email}</h2><p>Close this and go back to the app.</p>`);
});

// --- Stripe webhook handler (if stripe configured) ---
// Must set your endpoint in Stripe dashboard to /api/webhook
app.post("/api/webhook", (req, res) => {
  if (!stripe) return res.status(400).send("stripe not configured");
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature error:", err && err.message);
    return res.status(400).send(`Webhook Error: ${err && err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email;
    if (email) {
      activateUserByEmail.run(email);
      // update payment row
      const stmt = db.prepare("UPDATE payments SET status = 'paid' WHERE provider_ref = ?");
      stmt.run(session.id);
      console.log("Activated user via checkout:", email);
    }
  }

  res.json({ received: true });
});

// --- Simple auth endpoints (signup is payment-gated in client) ---
// Login (very minimal): takes email and returns JWT if user exists and is active
app.post("/api/login", (req, res) => {
  const email = (req.body.email || "").toLowerCase();
  if (!email) return res.status(400).json({ error: "email required" });
  const user = getUserByEmail.get(email);
  if (!user) return res.status(404).json({ error: "user not found (pay to create account)" });
  if (!user.is_active) return res.status(403).json({ error: "account not active - complete payment" });
  const token = createJwt(user);
  res.json({ token, user: { id: user.id, email: user.email, publicKey: user.public_key } });
});

// Save user public key (client-generated key for E2EE)
app.post("/api/me/pubkey", (req, res) => {
  const auth = req.headers.authorization || "";
  const tok = auth.replace("Bearer ", "");
  const payload = verifyJwt(tok);
  if (!payload) return res.status(401).json({ error: "unauth" });
  const pk = req.body.publicKey;
  if (!pk) return res.status(400).json({ error: "publicKey required" });
  db.prepare("UPDATE users SET public_key = ? WHERE id = ?").run(pk, payload.id);
  res.json({ ok: true });
});

// get user public key
app.get("/api/user/:id/pubkey", (req, res) => {
  const u = getUserById.get(req.params.id);
  if (!u) return res.status(404).json({ error: "user not found" });
  res.json({ publicKey: u.public_key, id: u.id, email: u.email });
});

// create/get conversation between two users
app.post("/api/conversation", (req, res) => {
  const { a, b } = req.body; // user ids
  if (!a || !b) return res.status(400).json({ error: "a & b required" });
  // ensure deterministic conv id (sort)
  const sorted = [a, b].sort();
  const convId = `${sorted[0]}_${sorted[1]}`;
  createConversation.run(convId, sorted[0], sorted[1]);
  res.json({ id: convId });
});

// serve minimal UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- start http + socket.io ---
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// map userId -> socketId
const userSockets = new Map();

io.on("connection", (socket) => {
  console.log("socket connected", socket.id);

  socket.on("auth", (data) => {
    const token = data && data.token;
    const payload = verifyJwt(token);
    if (!payload) {
      socket.emit("auth:fail");
      socket.disconnect();
      return;
    }
    socket.userId = payload.id;
    userSockets.set(payload.id, socket.id);
    socket.emit("auth:ok");
    console.log("socket auth ok for", payload.email);
  });

  // send encrypted message object: { convId, to, ciphertext, nonce }
  socket.on("send_message", (msg) => {
    if (!socket.userId) return;
    const convId = msg.convId;
    const to = msg.to;
    const ciphertext = msg.ciphertext;
    const nonce = msg.nonce;
    if (!convId || !to || !ciphertext || !nonce) return;

    const mid = uuidv4();
    insertMessage.run(mid, convId, socket.userId, ciphertext, nonce);

    const toSocketId = userSockets.get(to);
    if (toSocketId) {
      io.to(toSocketId).emit("message", { id: mid, convId, from: socket.userId, ciphertext, nonce, createdAt: Date.now() });
    }
  });

  socket.on("disconnect", () => {
    if (socket.userId) userSockets.delete(socket.userId);
  });
});

// start server
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT} (PUBLIC_URL=${PUBLIC_URL})`);
  if (!stripe) console.log("Stripe not configured — running in MOCK payment mode. Set STRIPE_SECRET to enable Stripe.");
});
