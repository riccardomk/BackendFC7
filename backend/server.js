
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
  const db = loadDb();
  // Unisci tutti gli utenti registrati con quelli che hanno punti
  const allUsernames = Array.from(new Set([
    ...db.users.map(u => u.name),
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
// === LOGICA FINESTRE DI MERCATO ===
const mercatoWindows = [
  { start: '2025-09-01T00:00:00Z', end: '2025-09-08T23:59:59Z' },
  { start: '2025-12-01T00:00:00Z', end: '2025-12-08T23:59:59Z' },
  { start: '2026-03-01T00:00:00Z', end: '2026-03-08T23:59:59Z' }
];
function isMercatoOpen(now = new Date()) {
  return mercatoWindows.some(win => new Date(win.start) <= now && now <= new Date(win.end));
}

// === LOGICA LIMITI CAMBI ===
const MAX_CAMBI_PER_WINDOW = 6;

app.post('/market/:username', (req, res) => {
  const username = req.params.username;
  const { credits, selected, confirmed, vendita, acquisto, valoreVendita, valoreAcquisto } = req.body;
  if (!username) return res.status(400).json({ error: 'Username mancante' });
  let data = loadMarketData();
  // --- FASE INIZIALE: salvataggio sempre libero finché non confermato ---
  if (!data.users[username] || !data.users[username].confirmed) {
    data.users[username] = {
      credits,
      selected,
      confirmed: !!confirmed,
      cambi: data.users[username]?.cambi || 0,
      lastWindow: data.users[username]?.lastWindow || null
    };
    saveMarketData(data);
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
  saveMarketData(data);
  res.json({ ok: true, credits: data.users[username].credits, cambi: data.users[username].cambi });
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
  // Leggi mercato per validare club posseduti
  const marketData = loadMarketData();
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
  if (formationData[userId] && formationData[userId].confirmed) {
    return res.status(403).json({ error: 'Formazione già confermata per questo turno' });
  }
  formationData[userId] = {
    starters,
    confirmed: true,
    timestamp: new Date().toISOString()
  };
  saveFormationData(formationData);
  res.json({ ok: true, starters });
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

// ===== AVVIO SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
