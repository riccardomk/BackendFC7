
import express from 'express';
import cors from 'cors';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- UTENTI (LOGIN/REGISTER) ---
const DB_FILE = path.join(__dirname, 'db.json');
function loadDb() {
  if (!fs.existsSync(DB_FILE)) return { users: [], markets: {} };
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Login
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e password obbligatori' });
  const db = loadDb();
  const user = db.users.find(u => u.name === name && u.password === password);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
  res.json({ user });
});

// Register
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
  const db = loadDb();
  if (db.users.find(u => u.name === name)) return res.status(409).json({ error: 'Nome profilo già registrato' });
  if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email già registrata' });
  const newUser = { name, email, password, id: name };
  db.users.push(newUser);
  saveDb(db);
  res.json({ user: newUser });
});
app.use(cors());
app.use(express.json({ limit: '10mb' }));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const USERS_FILE = path.join(__dirname, 'users-profile-pics.json');
const MARKET_FILE = path.join(__dirname, 'market-data.json');

// --- FOTO PROFILO ---
function saveUserProfilePic(username, url) {
  let data = { users: {} };
  if (fs.existsSync(USERS_FILE)) {
    data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  }
  data.users[username] = url;
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}
function getUserProfilePic(username) {
  if (!fs.existsSync(USERS_FILE)) return null;
  const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  return data.users[username] || null;
}

// --- MERCATO ---
function loadMarketData() {
  if (!fs.existsSync(MARKET_FILE)) return { users: {} };
  return JSON.parse(fs.readFileSync(MARKET_FILE, 'utf8'));
}
function saveMarketData(data) {
  fs.writeFileSync(MARKET_FILE, JSON.stringify(data, null, 2));
}

// Salva/aggiorna dati mercato per utente
app.post('/market/:username', (req, res) => {
  const username = req.params.username;
  const { credits, selected, confirmed } = req.body;
  if (!username) return res.status(400).json({ error: 'Username mancante' });
  let data = loadMarketData();
  data.users[username] = { credits, selected, confirmed };
  saveMarketData(data);
  res.json({ ok: true });
});
// Recupera dati mercato per utente
app.get('/market/:username', (req, res) => {
  const username = req.params.username;
  const data = loadMarketData();
  const userData = data.users[username];
  if (!userData) return res.status(404).json({ error: 'Nessun dato mercato per questo utente' });
  res.json(userData);
});

// --- FOTO PROFILO ---
app.post('/upload-profile-pic', async (req, res) => {
  try {
    const { image, username } = req.body;
    if (!image || !username) {
      return res.status(400).json({ error: 'Immagine o username mancante' });
    }
    const uploadRes = await cloudinary.uploader.upload(image, {
      folder: 'profile_pics',
      overwrite: true,
      resource_type: 'image',
    });
    saveUserProfilePic(username, uploadRes.secure_url);
    res.json({ url: uploadRes.secure_url });
  } catch (error) {
    res.status(500).json({ error: 'Errore durante l\'upload: ' + error.message });
  }
});
app.get('/profile-pic/:username', (req, res) => {
  const username = req.params.username;
  const url = getUserProfilePic(username);
  if (url) {
    res.json({ url });
  } else {
    res.status(404).json({ error: 'Foto profilo non trovata' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
