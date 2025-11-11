// ===== ROUTE ADMIN: INVIO NOTIFICA DI TEST A TUTTI =====
app.post('/admin/send-test-notification-all', async (req, res) => {
  const db = await connectMongo();
  const users = await db.collection('users').find({ fcmToken: { $exists: true } }).toArray();
  let success = 0, fail = 0;
  for (const user of users) {
    try {
      await sendPushNotification(
        user.fcmToken,
        'Schiera la tua squadra!',
        'Ricordati di schierare la formazione per la prossima giornata.',
        { type: 'reminder_formazione' }
      );
      success++;
    } catch (e) {
      fail++;
    }
  }
  res.json({ ok: true, sent: success, failed: fail });
});
// ===== ROUTE ADMIN: INVIO NOTIFICA DI TEST =====
app.post('/admin/send-test-notification', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username mancante' });
  const db = await connectMongo();
  const user = await db.collection('users').findOne({ name: username });
  if (!user || !user.fcmToken) return res.status(404).json({ error: 'Token FCM non trovato per questo utente' });
  try {
    await sendPushNotification(
      user.fcmToken,
      'Schiera la tua squadra!',
      'Ricordati di schierare la formazione per la prossima giornata.',
      { type: 'reminder_formazione' }
    );
    res.json({ ok: true, message: 'Notifica inviata!' });
  } catch (e) {
    res.status(500).json({ error: 'Errore invio notifica', details: e.message });
  }
});
// ===== IMPORTS ALL'INIZIO =====
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import { MongoClient } from 'mongodb';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

// ===== IMPORT FCM (Firebase Cloud Messaging) =====
// import fetch from 'node-fetch'; // rimosso, gestito sotto

// Configurazione FCM
const FCM_SERVER_KEY = process.env.FCM_SERVER_KEY;

// Funzione per inviare una notifica push tramite FCM
async function sendPushNotification(token, title, body, data = {}) {
  const message = {
    to: token,
    notification: {
      title,
      body
    },
    data
  };
  const res = await fetch('https://fcm.googleapis.com/fcm/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `key=${FCM_SERVER_KEY}`
    },
    body: JSON.stringify(message)
  });
  const result = await res.json();
  if (!res.ok) {
    console.error('Errore invio FCM:', result);
  } else {
    console.log('Notifica FCM inviata:', result);
  }
}



// ===== __filename e __dirname =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import dinamico di fetch SOLO dopo che path è definito
let fetch;
try {
  fetch = (await import('node-fetch')).default;
} catch (e) {
  console.error("node-fetch non trovato, provo a installarlo...");
  const { execSync } = await import('child_process');
  execSync('npm install node-fetch@3', { stdio: 'inherit' });
  fetch = (await import('node-fetch')).default;
}

const CALENDAR_FILES = {
  'Serie A': path.join(__dirname, 'calendar-seriea.json'),
  'Premier League': path.join(__dirname, 'calendar-premier.json'),
  'LaLiga': path.join(__dirname, 'calendar-laliga.json'),
  'Bundesliga': path.join(__dirname, 'calendar-bundesliga.json'),
  'Ligue 1': path.join(__dirname, 'calendar-ligue1.json'),
};
const FOOTBALL_DATA_API = 'https://api.football-data.org/v4/competitions';
const FOOTBALL_DATA_CODES = {
  'Serie A': 'SA',
  'Premier League': 'PL',
  'LaLiga': 'PD',
  'Bundesliga': 'BL1',
  'Ligue 1': 'FL1',
};
const FOOTBALL_DATA_TOKEN = process.env.FOOTBALL_DATA_TOKEN || '81ed2d1e396e4164b91e079b249038df';
async function fetchCalendar(league, file) {
  const code = FOOTBALL_DATA_CODES[league];
  if (!code) return [];
  try {
    const res = await fetch(`${FOOTBALL_DATA_API}/${code}/matches?season=2025`, {
      headers: { 'X-Auth-Token': FOOTBALL_DATA_TOKEN }
    });
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    // Estrarre week e date
    const matches = data.matches || [];
    // Raggruppa per giornata
    const byWeek = {};
    for (const m of matches) {
      if (!byWeek[m.matchday]) byWeek[m.matchday] = [];
      byWeek[m.matchday].push(m.utcDate);
    }
    // Per ogni giornata, prendi la data più vicina (prima partita)
    const result = Object.entries(byWeek).map(([week, dates]) => ({
      week: parseInt(week),
      date: dates.sort()[0]
    }));
    // Salva su file
    fs.writeFileSync(file, JSON.stringify(result, null, 2));
    return result;
  } catch (e) {
    console.error('Errore fetch calendario', league, e.message);
    return [];
  }
}
async function loadCalendari() {
  const calendari = {};
  for (const [league, file] of Object.entries(CALENDAR_FILES)) {
    if (fs.existsSync(file)) {
      calendari[league] = JSON.parse(fs.readFileSync(file, 'utf8'));
    } else {
      // Scarica e crea file se mancante
      calendari[league] = await fetchCalendar(league, file);
    }
  }
  return calendari;
}
// Caricamento asincrono all'avvio
let CALENDARI = {};
await (async () => {
  CALENDARI = await loadCalendari();
})();
// Funzione di controllo per segnalare se manca una settimana comune
function checkCalendariCommonWeek() {
  const weeks = {};
  for (const league in CALENDARI) {
    for (const g of CALENDARI[league]) {
      if (!weeks[g.week]) weeks[g.week] = [];
      weeks[g.week].push(league);
    }
  }
  const totalLeagues = Object.keys(CALENDARI).length;
  const commonWeeks = Object.entries(weeks).filter(([week, leagues]) => leagues.length === totalLeagues);
  if (commonWeeks.length === 0) {
    console.warn('ATTENZIONE: Nessuna settimana comune tra i calendari! Nessuno potrà inviare la formazione finché non allinei le giornate.');
  } else {
    const next = commonWeeks[0][0];
    console.log('Prossima settimana comune disponibile per la formazione:', next);
  }
}
// Controllo all’avvio del server
checkCalendariCommonWeek();
// Trova la prossima settimana comune e la prima partita (solo se tutte le leghe hanno la giornata)
function getNextCommonWeekAndFirstMatch() {
  // Trova la prossima settimana comune
  const weeks = {};
  for (const league in CALENDARI) {
    for (const g of CALENDARI[league]) {
      if (!weeks[g.week]) weeks[g.week] = [];
      weeks[g.week].push({ league, date: g.date });
    }
  }
  const totalLeagues = Object.keys(CALENDARI).length;
  const now = new Date();
  const commonWeeks = Object.entries(weeks)
    .filter(([week, arr]) => arr.length === totalLeagues)
    .map(([week, arr]) => ({
      week: parseInt(week),
      dates: arr.map(x => x.date)
    }))
    // Ordina per data della prima partita della settimana
    .sort((a, b) => {
      const dateA = new Date(a.dates.sort()[0]);
      const dateB = new Date(b.dates.sort()[0]);
      return dateA - dateB;
    });
  // Trova la prima settimana comune con data >= oggi
  const next = commonWeeks.find(w => new Date(w.dates.sort()[0]) >= now);
  if (!next) return null;
  const firstMatch = new Date(next.dates.sort()[0]);
  return { week: next.week, firstMatch };
}



// ===== COSTANTI FILE =====
//const RANKING_FILE = path.join(__dirname, 'ranking-data.json');
const MONGO_URI = process.env.MONGO_URI || 'INSERISCI_LA_TUA_STRINGA_DI_CONNESSIONE_MONGODB_ATLAS';
const MONGO_DB = process.env.MONGO_DB || 'fantaclub';
let mongoClient, mongoDb;
async function connectMongo() {
  if (!mongoClient) {
    mongoClient = new MongoClient(MONGO_URI);
    await mongoClient.connect();
    mongoDb = mongoClient.db(MONGO_DB);
  }
  return mongoDb;
}
const USERS_FILE = path.join(__dirname, 'users-profile-pics.json');
//const MARKET_FILE = path.join(__dirname, 'market-data.json');

// ===== FUNZIONI UTILI =====
// Funzioni ranking su MongoDB
async function loadRankingData() {
  const db = await connectMongo();
  const doc = await db.collection('ranking').findOne({ _id: 'main' });
  if (!doc) return { global: {}, weekly: {} };
  return { global: doc.global || {}, weekly: doc.weekly || {} };
}
async function saveRankingData(data) {
  const db = await connectMongo();
  await db.collection('ranking').updateOne(
    { _id: 'main' },
    { $set: { global: data.global, weekly: data.weekly } },
    { upsert: true }
  );
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
// Funzioni MongoDB utenti
async function findUserByName(name) {
  const db = await connectMongo();
  return await db.collection('users').findOne({ name });
}
async function findUserByEmail(email) {
  const db = await connectMongo();
  return await db.collection('users').findOne({ email });
}
async function insertUser(user) {
  const db = await connectMongo();
  await db.collection('users').insertOne(user);
}
function saveUserProfilePic(username, url) {
  let data = { users: {} };
  try {
    if (fs.existsSync(USERS_FILE)) {
      data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    }
  } catch (readErr) {
    console.error('Errore lettura file foto profilo:', readErr.message, readErr);
    throw readErr;
  }
  data.users[username] = url;
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
  } catch (writeErr) {
    console.error('Errore scrittura file foto profilo:', writeErr.message, writeErr);
    throw writeErr;
  }
}
function getUserProfilePic(username) {
  if (!fs.existsSync(USERS_FILE)) return null;
  const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  return data.users[username] || null;
}
// Funzioni mercato su MongoDB
async function loadMarketData() {
  const db = await connectMongo();
  const doc = await db.collection('market').findOne({ _id: 'main' });
  if (!doc) return { users: {} };
  return { users: doc.users || {} };
}
async function saveMarketData(data) {
  const db = await connectMongo();
  await db.collection('market').updateOne(
    { _id: 'main' },
    { $set: { users: data.users } },
    { upsert: true }
  );
}

// ===== INIZIALIZZAZIONE APP =====
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ===== MIDDLEWARE DI GESTIONE ERRORI CENTRALIZZATA =====
app.use((err, req, res, next) => {
  console.error('Errore:', err.message);
  res.status(500).json({ error: 'Errore interno del server. Riprova più tardi.' });
});

// ===== CONFIG CLOUDINARY =====
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
// Log di verifica variabili Cloudinary
console.log('CLOUDINARY_CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME);
console.log('CLOUDINARY_API_KEY:', process.env.CLOUDINARY_API_KEY);
console.log('CLOUDINARY_API_SECRET:', process.env.CLOUDINARY_API_SECRET ? '[PRESENTE]' : '[MANCANTE]');

// ===== ROUTE UTENTI (LOGIN/REGISTER) =====
// ===== ROUTE VERIFICA PASSWORD =====
app.post('/verify-password', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, error: 'Username e password obbligatori' });
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ success: false, error: 'Input non valido' });
  const user = await findUserByName(username);
  if (!user) return res.status(401).json({ success: false, error: 'Credenziali non valide' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, error: 'Credenziali non valide' });
  return res.json({ success: true });
});
app.post('/login', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e password obbligatori' });
  if (typeof name !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Input non valido' });
  const user = await findUserByName(name);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenziali non valide' });
  const { password: _, ...userSafe } = user;
  res.json({ user: userSafe });
});
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
  if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Input non valido' });
  if (name.length < 3 || password.length < 6) return res.status(400).json({ error: 'Nome o password troppo corti' });
  // Blocco nomi vietati
  const forbidden = [
    // Italiano
    'dio', 'gesu', 'madonna', 'cristo', 'porco', 'bestemmia', 'cane', 'merda', 'culo', 'puttana', 'troia', 'vaffanculo', 'stronzo', 'bastardo', 'coglione', 'idiota', 'stupido', 'deficiente', 'cretino', 'scemo', 'pene', 'vagina', 'sesso', 'porn', 'fanculo', 'suca', 'minchia', 'maledetto', 'inferno', 'satan', 'lucifero', 'diavolo', 'demonio', 'blasfemia',
    // Inglese (solo le peggiori)
    'fuck', 'shit', 'bitch', 'asshole', 'bastard', 'dick', 'pussy', 'cunt', 'slut', 'whore', 'fag', 'nigger', 'negro', 'faggot', 'rape'
  ];
  const lowerName = name.toLowerCase();
  if (forbidden.some(word => lowerName.includes(word))) {
    return res.status(400).json({ error: 'Nome utente non consentito.' });
  }
  if (await findUserByName(name)) return res.status(409).json({ error: 'Nome profilo già registrato' });
  if (await findUserByEmail(email)) return res.status(409).json({ error: 'Email già registrata' });
  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { name, email, password: hashedPassword, id: name };
  await insertUser(newUser);
  const { password: _, ...userSafe } = newUser;
  res.json({ user: userSafe });
});

// ===== ROUTE RANKING =====
app.get('/ranking/global', async (req, res) => {
  try {
    const ranking = await loadRankingData();
    // Prendi tutti gli utenti registrati
    const db = await connectMongo();
    const users = await db.collection('users').find({}).toArray();
    const allUsernames = Array.from(new Set([
      ...users.map(u => u.name),
      ...Object.keys(ranking.global)
    ]));
    const arr = allUsernames.map(username => {
      const stats = ranking.global[username] || { punti: 0, golFatti: 0, golSubiti: 0, diffReti: 0 };
      return { username, ...stats };
    });
    arr.sort((a, b) => {
      if (b.punti !== a.punti) return b.punti - a.punti;
      if (b.diffReti !== a.diffReti) return b.diffReti - a.diffReti;
      return b.golFatti - a.golFatti;
    });
    res.json(arr);
  } catch (e) {
    res.status(500).json({ error: 'Errore ranking global' });
  }
});
app.get('/ranking/weekly/:week', async (req, res) => {
  try {
    const week = req.params.week;
    const ranking = await loadRankingData();
    const weekData = ranking.weekly[week] || {};
    const arr = Object.entries(weekData).map(([username, stats]) => ({ username, ...stats }));
    arr.sort((a, b) => {
      if (b.punti !== a.punti) return b.punti - a.punti;
      if (b.diffReti !== a.diffReti) return b.diffReti - a.diffReti;
      return b.golFatti - a.golFatti;
    });
    res.json(arr);
  } catch (e) {
    res.status(500).json({ error: 'Errore ranking weekly' });
  }
});
app.post('/update-ranking', async (req, res) => {
  try {
    const { username, clubsSchierati, results, week } = req.body;
    if (!username || !clubsSchierati || !results || !week) return res.status(400).json({ error: 'Dati mancanti' });
    const ranking = await loadRankingData();
    const giornata = calcolaPunteggioGiornata(clubsSchierati, results);
    if (!ranking.weekly[week]) ranking.weekly[week] = {};
    ranking.weekly[week][username] = giornata;
    if (!ranking.global[username]) ranking.global[username] = { punti: 0, golFatti: 0, golSubiti: 0, diffReti: 0 };
    ranking.global[username].punti += giornata.punti;
    ranking.global[username].golFatti += giornata.golFatti;
    ranking.global[username].golSubiti += giornata.golSubiti;
    ranking.global[username].diffReti = ranking.global[username].golFatti - ranking.global[username].golSubiti;
    await saveRankingData(ranking);
    res.json({ ok: true, giornata, globale: ranking.global[username] });
  } catch (e) {
    res.status(500).json({ error: 'Errore update-ranking' });
  }
});

// ===== ROUTE MERCATO =====
// === LOGICA FINESTRE DI MERCATO ===
const mercatoWindows = [
  { start: '2025-09-01T00:00:00Z', end: '2025-09-08T23:59:59Z' },
  { start: '2025-12-01T00:00:00Z', end: '2025-12-08T23:59:59Z' },
  { start: '2026-03-01T00:00:00Z', end: '2026-03-08T23:59:59Z' }
];
function isMercatoOpen(now = new Date()) {
  return mercatoWindows.some(win => new Date(win.start) <= now && now <= new Date(win.end));
}
  // === LOGICA AGGIORNAMENTO VALORI SQUADRE IN BASE ALLA CLASSIFICA ===
  async function aggiornaValoriSquadreMercato() {
    // Carica ranking globale
    const ranking = await loadRankingData();
    // Carica dati mercato
    let marketData = await loadMarketData();
    // Ottieni array ordinato per posizione
    const arr = Object.entries(ranking.global).map(([username, stats]) => ({ username, ...stats }));
    arr.sort((a, b) => {
      if (b.punti !== a.punti) return b.punti - a.punti;
      if (b.diffReti !== a.diffReti) return b.diffReti - a.diffReti;
      return b.golFatti - a.golFatti;
    });
    // Esempio: tabella valori per posizione (personalizza come vuoi)
    const valoriPerPosizione = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    // Aggiorna valore per ogni squadra in base alla posizione
    arr.forEach((user, idx) => {
      // Trova la squadra associata all'utente (se la struttura lo consente)
      // Qui si assume che ogni username sia una squadra, altrimenti adatta la logica
      const squadra = user.username;
      const valore = valoriPerPosizione[idx] || 1;
      if (!marketData.squadre) marketData.squadre = {};
      if (!marketData.squadre[squadra]) marketData.squadre[squadra] = {};
      marketData.squadre[squadra].valoreAcquisto = valore;
    });
    await saveMarketData(marketData);
    console.log('Valori squadre aggiornati in base alla classifica!');
  }

// === LOGICA LIMITI CAMBI ===
const MAX_CAMBI_PER_WINDOW = 6;

app.post('/market/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const { credits, selected, confirmed, vendita, acquisto, valoreVendita, valoreAcquisto } = req.body;
    if (!username) return res.status(400).json({ error: 'Username mancante' });
    let data = await loadMarketData();
    // --- FASE INIZIALE: salvataggio sempre libero finché non confermato ---
    if (!data.users[username] || !data.users[username].confirmed) {
      data.users[username] = {
        credits,
        selected,
        confirmed: !!confirmed,
        cambi: data.users[username]?.cambi || 0,
        lastWindow: data.users[username]?.lastWindow || null
      };
      await saveMarketData(data);
      return res.json({ ok: true });
    }
    // --- DOPO LA CONFERMA: applica logica finestre e cambi ---
    if (!isMercatoOpen()) {
      return res.status(403).json({ error: 'Mercato chiuso. Attendi la prossima finestra.' });
    }
    // Identifica la finestra attuale
    const now = new Date();
    const currentWindow = mercatoWindows.find(win => new Date(win.start) <= now && now <= new Date(win.end));
    if (!currentWindow) {
      return res.status(403).json({ error: 'Mercato chiuso. Attendi la prossima finestra.' });
    }
    // Reset cambi se nuova finestra
    if (data.users[username].lastWindow !== currentWindow.start) {
      data.users[username].cambi = 0;
      data.users[username].lastWindow = currentWindow.start;
        // Aggiorna valori di mercato delle squadre in base alla classifica
        await aggiornaValoriSquadreMercato();
    }
    if (data.users[username].cambi >= MAX_CAMBI_PER_WINDOW) {
      return res.status(403).json({ error: 'Hai già effettuato il numero massimo di cambi per questa finestra di mercato.' });
    }
    // Gestione crediti e cambi
    if (vendita && valoreVendita) {
      data.users[username].credits += valoreVendita;
      data.users[username].cambi += 1;
      for (const lega in data.users[username].selected) {
        data.users[username].selected[lega] = data.users[username].selected[lega].filter(sq => sq !== vendita);
      }
    }
    if (acquisto && valoreAcquisto) {
      if (data.users[username].credits < valoreAcquisto) {
        return res.status(400).json({ error: 'Crediti insufficienti per acquistare questa squadra.' });
      }
      data.users[username].credits -= valoreAcquisto;
      data.users[username].cambi += 1;
      if (!data.users[username].selected[acquisto.lega]) data.users[username].selected[acquisto.lega] = [];
      data.users[username].selected[acquisto.lega].push(acquisto.nome);
    }
    if (typeof confirmed !== 'undefined') {
      data.users[username].confirmed = confirmed;
    }
    await saveMarketData(data);
    res.json({ ok: true, credits: data.users[username].credits, cambi: data.users[username].cambi });
  } catch (e) {
    res.status(500).json({ error: 'Errore mercato' });
  }
});
app.get('/market/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const data = await loadMarketData();
    const userData = data.users[username];
    if (!userData) return res.status(404).json({ error: 'Nessun dato mercato per questo utente' });
    res.json(userData);
  } catch (e) {
    res.status(500).json({ error: 'Errore mercato get' });
  }
});

// ===== ROUTE FOTO PROFILO =====
app.post('/upload-profile-pic', async (req, res) => {
  try {
    const { image, username } = req.body;
    if (!image || !username) {
      console.error('Upload foto profilo: immagine o username mancante', { image, username });
      return res.status(400).json({ error: 'Immagine o username mancante' });
    }
    let uploadRes;
    try {
      uploadRes = await cloudinary.uploader.upload(image, {
        folder: 'profile_pics',
        overwrite: true,
        resource_type: 'image',
      });
    } catch (cloudErr) {
      console.error('Errore Cloudinary:', cloudErr.message, cloudErr);
      return res.status(500).json({ error: 'Errore Cloudinary: ' + cloudErr.message });
    }
    try {
      saveUserProfilePic(username, uploadRes.secure_url);
    } catch (saveErr) {
      console.error('Errore salvataggio URL foto profilo:', saveErr.message, saveErr);
      return res.status(500).json({ error: 'Errore salvataggio foto profilo: ' + saveErr.message });
    }
    res.json({ url: uploadRes.secure_url });
  } catch (error) {
    console.error('Errore generico upload foto profilo:', error.message, error);
    res.status(500).json({ error: 'Errore durante l\'upload: ' + error.message });
  }
});

// ===== ROUTE REGISTRAZIONE TOKEN FCM =====
app.post('/register-fcm-token', async (req, res) => {
  const { username, fcmToken } = req.body;
  if (!username || !fcmToken) return res.status(400).json({ error: 'Dati mancanti' });
  const db = await connectMongo();
  await db.collection('users').updateOne(
    { name: username },
    { $set: { fcmToken } },
    { upsert: true }
  );
  res.json({ ok: true });
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

// ===== ROUTE FORMAZIONE: Salva la formazione confermata per utente =====
import formationFs from 'fs';
const FORMATION_FILE = path.join(__dirname, 'formation-data.json');

function loadFormationData() {
  if (!formationFs.existsSync(FORMATION_FILE)) return {};
  return JSON.parse(formationFs.readFileSync(FORMATION_FILE, 'utf8'));
}
function saveFormationData(data) {
  formationFs.writeFileSync(FORMATION_FILE, JSON.stringify(data, null, 2));
}

// Salva la formazione solo se non già confermata per il turno
app.post('/formation/:userId', (req, res) => {
  const userId = req.params.userId;
  const { starters, confirmed } = req.body;
  if (!userId || !Array.isArray(starters) || starters.length !== 11) {
    return res.status(400).json({ error: 'Dati formazione non validi (serve 11 titolari)' });
  }
  // --- LOGICA BLOCCO FORMAZIONE: SOLO SE TUTTI I CAMPIONATI HANNO UNA GIORNATA (SETTIMANA COMUNE) ---
  const next = getNextCommonWeekAndFirstMatch();
  if (!next) {
    return res.status(403).json({ error: 'Non tutti i campionati hanno una giornata attiva questa settimana.' });
  }
  const now = new Date();
  const limite = new Date(next.firstMatch.getTime() - 30 * 60 * 1000); // 30 minuti prima
  if (now > limite) {
    return res.status(403).json({ error: 'Tempo scaduto: la formazione poteva essere inviata solo fino a 30 minuti prima della prima partita.' });
  }
  (async () => {
    // Leggi mercato per validare club posseduti (online)
    const marketData = await loadMarketData();
    const userMarket = marketData.users[userId];
    if (!userMarket || !userMarket.selected) {
      return res.status(400).json({ error: 'Nessun club acquistato dal mercato' });
    }
    // Appiattisci tutti i club acquistati
    const allOwnedClubs = Object.values(userMarket.selected).flat();
    // Verifica che tutti i club schierati siano tra quelli acquistati
    const valid = starters.every(club => allOwnedClubs.includes(club));
    if (!valid) {
      return res.status(400).json({ error: 'Almeno un club non è stato acquistato dal mercato' });
    }
    // Carica formazioni già inviate
    const formationData = loadFormationData();
    // Permetti sempre la sovrascrittura fino alla deadline
    formationData[userId] = {
      starters,
      confirmed: true,
      timestamp: new Date().toISOString()
    };
    saveFormationData(formationData);
    res.json({ ok: true, starters });
  })();
});



// Route GET per la deadline della formazione (prossima settimana comune e deadline invio)
app.get('/formation/deadline', (req, res) => {
  const next = getNextCommonWeekAndFirstMatch();
  if (!next) {
    return res.json({ deadline: null, week: null });
  }
  // Deadline: 30 minuti prima della prima partita della settimana comune
  const deadline = new Date(next.firstMatch.getTime() - 30 * 60 * 1000);
  res.json({ deadline: deadline.toISOString(), week: next.week });
});

// Endpoint diagnostico per admin: mostra settimane comuni e stato allineamento calendari
app.get('/formation/diagnostics', (req, res) => {
  const weeks = {};
  for (const league in CALENDARI) {
    for (const g of CALENDARI[league]) {
      if (!weeks[g.week]) weeks[g.week] = [];
      weeks[g.week].push(league);
    }
  }
  const totalLeagues = Object.keys(CALENDARI).length;
  const commonWeeks = Object.entries(weeks)
    .filter(([week, leagues]) => leagues.length === totalLeagues)
    .map(([week, leagues]) => parseInt(week));
  res.json({
    totalLeagues,
    weeks,
    commonWeeks,
    nextCommonWeek: commonWeeks.length > 0 ? commonWeeks[0] : null,
    diagnostics: commonWeeks.length === 0
      ? 'ATTENZIONE: Nessuna settimana comune tra i calendari! Nessuno potrà inviare la formazione finché non allinei le giornate.'
      : `Prossima settimana comune disponibile per la formazione: ${commonWeeks[0]}`
  });
});

// Route GET per recuperare la formazione confermata di un utente
app.get('/formation/:userId', (req, res) => {
  const userId = req.params.userId;
  const formationData = loadFormationData();
  if (!formationData[userId]) {
    return res.status(404).json({ error: 'Nessuna formazione confermata trovata' });
  }
  res.json(formationData[userId]);
});

// ===== FUNZIONE RESET FINE STAGIONE =====
app.post('/admin/reset-stagione', async (req, res) => {
  try {
    // 1. Salva lo storico delle classifiche
    const ranking = await loadRankingData();
    const year = new Date().getFullYear();
    const storicoPath = path.join(__dirname, `ranking-storico-${year}.json`);
    fs.writeFileSync(storicoPath, JSON.stringify(ranking, null, 2));

    // 2. Recupera automaticamente le squadre partecipanti ai 5 campionati
    const LEAGUE_CODES = ['SA', 'PL', 'PD', 'BL1', 'FL1'];
    let squadreMassimaLega = [];
    for (const code of LEAGUE_CODES) {
      const url = `https://api.football-data.org/v4/competitions/${code}/teams?season=${year}`;
      const res = await fetch(url, { headers: { 'X-Auth-Token': FOOTBALL_DATA_TOKEN } });
      if (res.ok) {
        const data = await res.json();
        const teams = data.teams.map(t => t.name);
        squadreMassimaLega = squadreMassimaLega.concat(teams);
      }
    }

    let marketData = await loadMarketData();
    marketData.squadre = marketData.squadre || {};
    // Rimuovi squadre retrocesse
    Object.keys(marketData.squadre).forEach(sq => {
      if (!squadreMassimaLega.includes(sq)) {
        delete marketData.squadre[sq];
      }
    });
    // Aggiungi squadre promosse (se non già presenti)
    squadreMassimaLega.forEach(sq => {
      if (!marketData.squadre[sq]) {
        marketData.squadre[sq] = { valoreAcquisto: 1 };
      }
    });
    await saveMarketData(marketData);

    // 3. Reset ranking e mercato
    await saveRankingData({ global: {}, weekly: {} });
    marketData.users = {};
    await saveMarketData(marketData);

    res.json({ ok: true, storico: storicoPath, squadreAcquistabili: squadreMassimaLega });
  } catch (e) {
    res.status(500).json({ error: 'Errore reset stagione', details: e.message });
  }
});

// ===== AVVIO SERVER =====

// ===== LOGICA NOTIFICHE AUTOMATICHE (calcolo date/orari chiave) =====
function getNotificationSchedule() {
  // Calcola date/orari per notifiche formazione
  const nextFormation = getNextCommonWeekAndFirstMatch();
  let formationNotifications = [];
  if (nextFormation) {
    const firstMatch = nextFormation.firstMatch;
    // Reminder settimanale: 3 giorni prima
    const reminderDate = new Date(firstMatch.getTime() - 3 * 24 * 60 * 60 * 1000);
    // Alert 2 ore prima della deadline (deadline = 30 min prima della prima partita)
    const deadline = new Date(firstMatch.getTime() - 30 * 60 * 1000);
    const alert2h = new Date(deadline.getTime() - 2 * 60 * 60 * 1000);
    formationNotifications.push({ type: 'reminder_formazione', date: reminderDate });
    formationNotifications.push({ type: 'alert_2h_formazione', date: alert2h });
    formationNotifications.push({ type: 'deadline_formazione', date: deadline });
    // Feedback a fine giornata: dopo la fine della giornata (es. 2 ore dopo la fine partita)
    // Per semplicità, prendiamo la data della prima partita + 1 giorno
    const feedbackDate = new Date(firstMatch.getTime() + 24 * 60 * 60 * 1000);
    formationNotifications.push({ type: 'feedback_giornata', date: feedbackDate });
  }

  // Calcola date/orari per notifiche mercato
  let mercatoNotifications = [];
  for (const win of mercatoWindows) {
    const start = new Date(win.start);
    const end = new Date(win.end);
    // 3 giorni prima apertura
    const threeDaysBefore = new Date(start.getTime() - 3 * 24 * 60 * 60 * 1000);
    // 10 minuti prima apertura
    const tenMinBeforeOpen = new Date(start.getTime() - 10 * 60 * 1000);
    // 10 minuti prima chiusura
    const tenMinBeforeClose = new Date(end.getTime() - 10 * 60 * 1000);
    mercatoNotifications.push({ type: 'mercato_3gg_apertura', date: threeDaysBefore, window: win });
    mercatoNotifications.push({ type: 'mercato_10min_apertura', date: tenMinBeforeOpen, window: win });
    mercatoNotifications.push({ type: 'mercato_10min_chiusura', date: tenMinBeforeClose, window: win });
  }

  return { formationNotifications, mercatoNotifications };
}

// ===== ROUTINE BASE PER INVIO NOTIFICHE (solo log, da integrare con push) =====

// ===== ROUTINE INVIO NOTIFICHE PUSH =====
async function notificationRoutine() {
  const now = new Date();
  const { formationNotifications, mercatoNotifications } = getNotificationSchedule();
  // Recupera tutti gli utenti e i loro token push (da DB)
  const db = await connectMongo();
  const users = await db.collection('users').find({ fcmToken: { $exists: true } }).toArray();
  // Notifiche formazione
  for (const n of formationNotifications) {
    if (Math.abs(n.date - now) < 60 * 1000) {
      for (const user of users) {
        let title = '', body = '';
        if (n.type === 'reminder_formazione') {
          title = 'Schiera la tua squadra!';
          body = 'Ricordati di schierare la formazione per la prossima giornata.';
        } else if (n.type === 'alert_2h_formazione') {
          title = 'Mancano 2 ore alla deadline!';
          body = 'Hai ancora tempo per schierare la formazione.';
        } else if (n.type === 'deadline_formazione') {
          title = 'Deadline formazione!';
          body = 'Ultimi minuti per schierare la formazione.';
        } else if (n.type === 'feedback_giornata') {
          title = 'Risultati giornata';
          body = 'Scopri i tuoi punti e la posizione in classifica.';
        }
        if (title && body) {
          await sendPushNotification(user.fcmToken, title, body, { type: n.type });
        }
      }
    }
  }
  // Notifiche mercato
  for (const n of mercatoNotifications) {
    if (Math.abs(n.date - now) < 60 * 1000) {
      for (const user of users) {
        let title = '', body = '';
        if (n.type === 'mercato_3gg_apertura') {
          title = 'Il mercato apre tra 3 giorni!';
          body = `Apertura: ${n.window.start}, Chiusura: ${n.window.end}`;
        } else if (n.type === 'mercato_10min_apertura') {
          title = 'Il mercato sta per aprire!';
          body = `Apertura: ${n.window.start}, Chiusura: ${n.window.end}`;
        } else if (n.type === 'mercato_10min_chiusura') {
          title = 'Il mercato sta per chiudere!';
          body = `Chiusura tra 10 minuti: ${n.window.end}`;
        }
        if (title && body) {
          await sendPushNotification(user.fcmToken, title, body, { type: n.type });
        }
      }
    }
  }
}

// Routine ogni minuto
setInterval(notificationRoutine, 60 * 1000);

const PORT = process.env.PORT || 1000;
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});

