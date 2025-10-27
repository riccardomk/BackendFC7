// ...existing code...
// ===== ROUTE FORMAZIONE (CONFERMA TITOLARI) =====
app.post('/formation/:username', (req, res) => {
  const username = req.params.username;
  const { starters, confirmed } = req.body;
  if (!username) return res.status(400).json({ error: 'Username mancante' });
  if (!Array.isArray(starters) || starters.length !== 11) {
    return res.status(400).json({ error: 'Devi schierare esattamente 11 titolari' });
  }
  let data = loadMarketData();
  // Blocca solo la formazione se già confermata
  if (data.users[username] && data.users[username].formationConfirmed) {
    return res.status(403).json({ error: 'Formazione già confermata, non modificabile' });
  }
  // Aggiorna solo la formazione titolare e il flag di conferma formazione
  data.users[username] = {
    ...data.users[username],
    starters,
    formationConfirmed: confirmed
  };
  saveMarketData(data);
  res.json({ ok: true });
});


// ===== IMPORTS ALL'INIZIO =====
import express from 'express';
import cors from 'cors';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ===== __filename e __dirname =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== COSTANTI FILE =====
const RANKING_FILE = path.join(__dirname, 'ranking-data.json');
const DB_FILE = path.join(__dirname, 'db.json');
const USERS_FILE = path.join(__dirname, 'users-profile-pics.json');
const MARKET_FILE = path.join(__dirname, 'market-data.json');

// ===== FUNZIONI UTILI =====
function loadRankingData() {
  if (!fs.existsSync(RANKING_FILE)) return { global: {}, weekly: {} };
  return JSON.parse(fs.readFileSync(RANKING_FILE, 'utf8'));
}
function saveRankingData(data) {
  fs.writeFileSync(RANKING_FILE, JSON.stringify(data, null, 2));
}
function calcolaPunteggioGiornata(clubsSchierati, results) {
  let punti = 0;
  let golFatti = 0;
  let golSubiti = 0;
  for (const club of clubsSchierati) {
    const res = results[club];
    if (!res) continue;
    if (res.esito === 'W') punti += 3;
    else if (res.esito === 'D') punti += 1;
    golFatti += res.gf;
    golSubiti += res.gs;
  }
  const diffReti = golFatti - golSubiti;
  return { punti, golFatti, golSubiti, diffReti };
}
function loadDb() {
  if (!fs.existsSync(DB_FILE)) return { users: [], markets: {} };
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
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
function loadMarketData() {
  if (!fs.existsSync(MARKET_FILE)) return { users: {} };
  return JSON.parse(fs.readFileSync(MARKET_FILE, 'utf8'));
}
function saveMarketData(data) {
  fs.writeFileSync(MARKET_FILE, JSON.stringify(data, null, 2));
}

// ===== INIZIALIZZAZIONE APP =====
const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ===== CONFIG CLOUDINARY =====
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ===== ROUTE UTENTI (LOGIN/REGISTER) =====
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e password obbligatori' });
  const db = loadDb();
  const user = db.users.find(u => u.name === name && u.password === password);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
  res.json({ user });
});
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

// ===== ROUTE RANKING =====
app.get('/ranking/global', (req, res) => {
  const ranking = loadRankingData();
  const arr = Object.entries(ranking.global).map(([username, stats]) => ({ username, ...stats }));
  arr.sort((a, b) => {
    if (b.punti !== a.punti) return b.punti - a.punti;
    if (b.diffReti !== a.diffReti) return b.diffReti - a.diffReti;
    return b.golFatti - a.golFatti;
  });
  res.json(arr);
});
app.get('/ranking/weekly/:week', (req, res) => {
  const week = req.params.week;
  const ranking = loadRankingData();
  const weekData = ranking.weekly[week] || {};
  const arr = Object.entries(weekData).map(([username, stats]) => ({ username, ...stats }));
  arr.sort((a, b) => {
    if (b.punti !== a.punti) return b.punti - a.punti;
    if (b.diffReti !== a.diffReti) return b.diffReti - a.diffReti;
    return b.golFatti - a.golFatti;
  });
  res.json(arr);
});
app.post('/update-ranking', (req, res) => {
  const { username, clubsSchierati, results, week } = req.body;
  if (!username || !clubsSchierati || !results || !week) return res.status(400).json({ error: 'Dati mancanti' });
  const ranking = loadRankingData();
  const giornata = calcolaPunteggioGiornata(clubsSchierati, results);
  if (!ranking.weekly[week]) ranking.weekly[week] = {};
  ranking.weekly[week][username] = giornata;
  if (!ranking.global[username]) ranking.global[username] = { punti: 0, golFatti: 0, golSubiti: 0, diffReti: 0 };
  ranking.global[username].punti += giornata.punti;
  ranking.global[username].golFatti += giornata.golFatti;
  ranking.global[username].golSubiti += giornata.golSubiti;
  ranking.global[username].diffReti = ranking.global[username].golFatti - ranking.global[username].golSubiti;
  saveRankingData(ranking);
  res.json({ ok: true, giornata, globale: ranking.global[username] });
});

// ===== ROUTE MERCATO =====
app.post('/market/:username', (req, res) => {
  const username = req.params.username;
  const { credits, selected, confirmed } = req.body;
  if (!username) return res.status(400).json({ error: 'Username mancante' });
  let data = loadMarketData();
  if (data.users[username] && data.users[username].confirmed) {
    return res.status(403).json({ error: 'Mercato già confermato, non modificabile' });
  }
  data.users[username] = { credits, selected, confirmed };
  saveMarketData(data);
  res.json({ ok: true });
});
app.get('/market/:username', (req, res) => {
  const username = req.params.username;
  const data = loadMarketData();
  const userData = data.users[username];
  if (!userData) return res.status(404).json({ error: 'Nessun dato mercato per questo utente' });
  res.json(userData);
});

// ===== ROUTE FOTO PROFILO =====
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

// ===== AVVIO SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
