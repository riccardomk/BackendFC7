// ===== IMPORTS ALL'INIZIO =====
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import { MongoClient } from 'mongodb';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import { createRequire } from 'module';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

// ===== IMPORT FCM (Firebase Cloud Messaging) =====
const require = createRequire(import.meta.url);
const jwt = require('jsonwebtoken');
// fetch è già disponibile in Node.js 25+ come globale

// Configurazione FCM - USA SERVICE ACCOUNT per HTTP v1 API  
const FCM_SERVER_KEY = process.env.FCM_SERVER_KEY; // Manteniamo per compatibilità
const FCM_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'fantafc-12c98';

// Service Account configurato dalle variabili d'ambiente
const SERVICE_ACCOUNT = {
  "type": "service_account", 
  "project_id": FCM_PROJECT_ID,
  "private_key": process.env.FIREBASE_PRIVATE_KEY,
  "client_email": process.env.FIREBASE_CLIENT_EMAIL,
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
};

// Funzione per generare token OAuth2 per Firebase HTTP v1 API
async function getAccessToken() {
  console.log('📧 Client Email:', SERVICE_ACCOUNT.client_email);
  console.log('🔐 Private Key disponibile:', !!SERVICE_ACCOUNT.private_key);
  
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: SERVICE_ACCOUNT.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };
  
  console.log('📋 JWT Payload:', JSON.stringify(payload, null, 2));
  
  const token = jwt.sign(payload, SERVICE_ACCOUNT.private_key, { algorithm: 'RS256' });
  console.log('✅ JWT generato:', token.substring(0, 50) + '...');
  
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: token
    })
  });
  
  const data = await response.json();
  console.log('📥 Risposta OAuth2:', JSON.stringify(data, null, 2));
  
  if (data.access_token) {
    console.log('✅ Access Token ottenuto:', data.access_token.substring(0, 20) + '...');
  } else {
    console.error('❌ Errore OAuth2:', data);
    throw new Error(`OAuth2 Error: ${data.error || 'Token non ricevuto'}`);
  }
  
  return data.access_token;
}

// Funzione per FCM HTTP v1 API con Service Account
async function sendPushNotification(token, title, body, data = {}) {
  console.log('🔄 Invio notifica FCM HTTP v1...');
  console.log('📱 Token destinatario:', token.substring(0, 30) + '...');
  console.log('🔑 Service Account Email:', SERVICE_ACCOUNT.client_email);
  console.log('🏷️ Project ID:', FCM_PROJECT_ID);
  
  try {
    // Genera Access Token OAuth2 con JWT
    const accessToken = await getAccessToken();
    console.log('✅ Access Token generato:', accessToken ? accessToken.substring(0, 20) + '...' : 'NULL');
    
    // Messaggio FCM HTTP v1 format
    const message = {
      message: {
        token: token,
        notification: {
          title: title,
          body: body
        },
        data: {
          ...data
        },
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            channel_id: 'default'
          }
        }
      }
    };
    
    console.log('📤 Payload FCM v1:', JSON.stringify(message, null, 2));
    
    // Invia tramite HTTP v1 API
    const response = await fetch(`https://fcm.googleapis.com/v1/projects/${FCM_PROJECT_ID}/messages:send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(message)
    });
    
    const responseText = await response.text();
    console.log('📥 Risposta FCM v1 Status:', response.status);
    console.log('📥 Risposta FCM v1 Raw:', responseText);
    
    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      console.error('❌ Errore parsing risposta:', parseError);
      throw new Error(`Risposta FCM non valida: ${responseText}`);
    }
    
    if (response.ok) {
      console.log('✅ Notifica FCM v1 inviata con successo!');
      return { success: 1, results: [result] }; // Formato compatibile
    } else {
      console.error('❌ Errore FCM v1:', result);
      throw new Error(`FCM v1 Error: ${result.error?.message || 'Unknown error'}`);
    }
  } catch (error) {
    console.error('❌ Errore completo FCM v1:', error.message);
    throw error;
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

// Funzione per trovare automaticamente l'ultima giornata finita per ogni lega
// Usa matchday fissi verificati per evitare rate limiting
async function getLastFinishedMatchdayForAllLeagues() {
  // Matchday verificati per fine novembre 2025 (28-29 nov)
  // Serie A: 13, Premier: 13, LaLiga: 14, Bundesliga: 12, Ligue 1: 13 (NON 14!)
  const matchdays = {
    'Serie A': 13,
    'Premier League': 13,
    'LaLiga': 14,
    'Bundesliga': 12,
    'Ligue 1': 13
  };
  
  console.log('📅 Uso matchday verificati per fine novembre 2025:');
  for (const [league, md] of Object.entries(matchdays)) {
    console.log(`  ${league}: matchday ${md}`);
  }
  
  return matchdays;
}

// Mappa delle stagioni per ogni lega (Bundesliga usa 2024, le altre 2025)
const LEAGUE_SEASONS = {
  'Serie A': 2025,
  'Premier League': 2025,
  'LaLiga': 2025,
  'Bundesliga': 2025,
  'Ligue 1': 2025
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

// ===== CONFIGURAZIONE EMAIL CON FETCH (NO SMTP) =====
// Render blocca le porte SMTP, uso API diretta SendGrid
async function sendResetEmail(email, resetToken, userName) {
  const resetLink = `fantafc://reset-password?token=${resetToken}`;
  
  // Se non hai SendGrid, usa questo workaround: salva il link e mostralo all'utente
  console.log(`[EMAIL DEBUG] Link reset per ${userName}: ${resetLink}`);
  
  // Provo con SendGrid API (se configurato)
  if (process.env.SENDGRID_API_KEY) {
    try {
      const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.SENDGRID_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          personalizations: [{
            to: [{ email: email }],
            subject: 'Reset Password - FantaFC'
          }],
          from: { email: process.env.EMAIL_USER || 'noreply@fantafc.com', name: 'FantaFC' },
          content: [{
            type: 'text/html',
            value: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #2575fc;">Reset Password FantaFC</h2>
                <p>Ciao <strong>${userName}</strong>,</p>
                <p>Hai richiesto di reimpostare la tua password. Clicca sul pulsante qui sotto per procedere:</p>
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${resetLink}" style="background-color: #2575fc; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reimposta Password</a>
                </div>
                <p style="color: #666; font-size: 14px;">Questo link è valido per 30 minuti.</p>
                <p style="color: #666; font-size: 14px;">Se non hai richiesto il reset della password, ignora questa email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #999; font-size: 12px;">FantaFC Team</p>
              </div>
            `
          }]
        })
      });
      
      if (response.ok) {
        console.log(`[EMAIL INVIATA] Reset password inviato a ${email}`);
        return true;
      } else {
        console.error('[ERRORE SENDGRID]', await response.text());
        return false;
      }
    } catch (error) {
      console.error('[ERRORE INVIO EMAIL]', error);
      return false;
    }
  }
  
  // Fallback: ritorna true ma logga il link (per testing)
  console.log(`[MODALITÀ DEBUG] Email non inviata, ma token generato. Link: ${resetLink}`);
  return true; // Ritorna true per permettere il flusso
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
  // Funzione helper per normalizzare stringhe
  const normalize = s => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/gi, '');
  
  let punti = 0;
  let golFatti = 0;
  let golSubiti = 0;
  
  for (const club of clubsSchierati) {
    let res = null;
    
    // 1. Prova match esatto con nome originale
    res = results[club];
    
    // 2. Se non trova, prova conversione con OLD_NAMES_MAPPING
    if (!res && OLD_NAMES_MAPPING[club]) {
      const officialName = OLD_NAMES_MAPPING[club];
      res = results[officialName];
      if (res) {
        console.log(`✅ Conversione: "${club}" → "${officialName}"`);
      }
    }
    
    // 3. Se ancora non trova, prova match normalizzato fuzzy
    if (!res) {
      const normalizedClub = normalize(club);
      const matchedKey = Object.keys(results).find(key => normalize(key) === normalizedClub);
      if (matchedKey) {
        res = results[matchedKey];
        console.log(`🔄 Match fuzzy: "${club}" → "${matchedKey}"`);
      }
    }
    
    if (!res) {
      console.log(`⚠️ Nessun risultato trovato per: "${club}"`);
      continue;
    }
    
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
async function saveUserProfilePic(username, url) {
  try {
    const db = await connectMongo();
    await db.collection('users').updateOne(
      { name: username },
      { $set: { profilePicUrl: url } },
      { upsert: false }
    );
    console.log(`✅ Foto profilo salvata per ${username}: ${url}`);
  } catch (err) {
    console.error('Errore salvataggio foto profilo MongoDB:', err.message, err);
    throw err;
  }
}
async function getUserProfilePic(username) {
  try {
    const db = await connectMongo();
    const user = await db.collection('users').findOne({ name: username });
    return user?.profilePicUrl || null;
  } catch (err) {
    console.error('Errore recupero foto profilo MongoDB:', err.message);
    return null;
  }
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
// Endpoint root per monitoraggio UptimeRobot
app.get('/', (req, res) => {
  res.status(200).send('BackendFC7 attivo');
});

// ===== ROUTE ADMIN: INVIO NOTIFICA DI TEST A TUTTI =====
app.post('/admin/send-test-notification-all', async (req, res) => {
  const db = await connectMongo();
  const users = await db.collection('users').find({ fcmToken: { $exists: true } }).toArray();
  let success = 0, fail = 0;
  
  console.log(`Trovati ${users.length} utenti totali con token FCM`);
  
  // Deduplicazione: raggruppa per token FCM unico per evitare duplicati
  const uniqueTokens = new Map();
  for (const user of users) {
    if (user.fcmToken && !uniqueTokens.has(user.fcmToken)) {
      uniqueTokens.set(user.fcmToken, user);
    }
  }
  
  console.log(`Token FCM unici: ${uniqueTokens.size} (eliminati ${users.length - uniqueTokens.size} duplicati)`);
  
  for (const [token, user] of uniqueTokens) {
    try {
      console.log(`Invio notifica a: ${user.name}, token: ${token.substring(0, 20)}...`);
      await sendPushNotification(
        token,
        'Schiera la tua squadra!',
        'Ricordati di schierare la formazione per la prossima giornata.',
        { type: 'reminder_formazione' }
      );
      success++;
      console.log(`✅ Notifica inviata con successo a ${user.name}`);
    } catch (e) {
      console.error(`❌ Errore invio notifica a ${user.name}:`, e.message);
      fail++;
    }
  }
  console.log(`Risultato finale: ${success} successi, ${fail} fallimenti`);
  res.json({ ok: true, sent: success, failed: fail, totalUsers: users.length, uniqueTokens: uniqueTokens.size });
});

// ===== ROUTE ADMIN: LISTA UTENTI E STATO TOKEN FCM =====
app.get('/admin/list-fcm-tokens', async (req, res) => {
  const db = await connectMongo();
  const users = await db.collection('users').find({}).toArray();
  const result = users.map(u => ({
    username: u.name,
    fcmToken: u.fcmToken || null
  }));
  res.json({ utenti: result });
});

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
  const { name, password, fcmToken } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e password obbligatori' });
  if (typeof name !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Input non valido' });
  const user = await findUserByName(name);
  if (!user) return res.status(401).json({ error: 'Credenziali non valide' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenziali non valide' });
  // Aggiorna fcmToken solo se è una stringa valida (non finto, non null, non vuoto)
  if (typeof fcmToken === 'string' && fcmToken && fcmToken.length > 30 && !fcmToken.startsWith('TEST_TOKEN')) {
    console.log('[DEBUG] /login received fcmToken valido per', name, '->', fcmToken);
    const db = await connectMongo();
    await db.collection('users').updateOne(
      { name },
      { $set: { fcmToken } }
    );
  } else {
    console.log('[DEBUG] /login fcmToken ignorato (non valido):', fcmToken);
  }
  const { password: _, ...userSafe } = user;
  res.json({ user: userSafe });
});

// ===== RECUPERO PASSWORD CON TOKEN E EMAIL =====
app.post('/forgot-password', async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length < 3) {
      return res.status(400).json({ error: 'Nome profilo non valido' });
    }
    
    const user = await findUserByName(name.trim());
    if (!user) {
      return res.status(404).json({ error: 'Utente non trovato' });
    }
    
    if (!user.email) {
      return res.status(400).json({ error: 'Nessuna email associata a questo profilo' });
    }
    
    // Genera token sicuro (32 caratteri esadecimali)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 30 * 60 * 1000; // 30 minuti
    
    // Salva token nel database
    const db = await connectMongo();
    await db.collection('users').updateOne(
      { name: user.name },
      { 
        $set: { 
          resetToken: resetToken,
          resetTokenExpiry: resetTokenExpiry
        } 
      }
    );
    
    // Invia email con link di reset
    const emailSent = await sendResetEmail(user.email, resetToken, user.name);
    
    const resetLink = `fantafc://reset-password?token=${resetToken}`;
    
    console.log(`[RESET PASSWORD] Token generato per ${user.name} - Email: ${user.email}`);
    console.log(`[RESET LINK] ${resetLink}`);
    
    res.json({ 
      success: true, 
      message: emailSent ? 'Email di reset inviata! Controlla la tua casella email.' : 'Token generato! Usa il link qui sotto.',
      email: user.email.replace(/(.{2}).*(@.*)/, '$1***$2'),
      resetLink: resetLink, // Ritorna il link per testing (RIMUOVERE IN PRODUZIONE)
      emailSent: emailSent
    });
  } catch (error) {
    console.error('[ERRORE RECUPERO PASSWORD]', error);
    res.status(500).json({ error: 'Errore del server' });
  }
});

// ===== VERIFICA TOKEN RESET PASSWORD =====
app.post('/verify-reset-token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Token mancante' });
    }
    
    const db = await connectMongo();
    const user = await db.collection('users').findOne({ resetToken: token });
    
    if (!user) {
      return res.status(404).json({ error: 'Token non valido' });
    }
    
    if (user.resetTokenExpiry < Date.now()) {
      return res.status(400).json({ error: 'Token scaduto. Richiedi un nuovo reset.' });
    }
    
    res.json({ 
      success: true, 
      userName: user.name 
    });
  } catch (error) {
    console.error('[ERRORE VERIFICA TOKEN]', error);
    res.status(500).json({ error: 'Errore del server' });
  }
});

// ===== RESET PASSWORD CON NUOVO PASSWORD =====
app.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token o password mancanti' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'La password deve essere di almeno 6 caratteri' });
    }
    
    const db = await connectMongo();
    const user = await db.collection('users').findOne({ resetToken: token });
    
    if (!user) {
      return res.status(404).json({ error: 'Token non valido' });
    }
    
    if (user.resetTokenExpiry < Date.now()) {
      return res.status(400).json({ error: 'Token scaduto. Richiedi un nuovo reset.' });
    }
    
    // Cripta la nuova password
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    
    // Aggiorna password e rimuovi token
    await db.collection('users').updateOne(
      { name: user.name },
      { 
        $set: { password: hashedPassword },
        $unset: { resetToken: '', resetTokenExpiry: '' }
      }
    );
    
    console.log(`[PASSWORD REIMPOSTATA] Utente: ${user.name}`);
    
    res.json({ 
      success: true, 
      message: 'Password reimpostata con successo!' 
    });
  } catch (error) {
    console.error('[ERRORE RESET PASSWORD]', error);
    res.status(500).json({ error: 'Errore del server' });
  }
});

app.post('/register', async (req, res) => {
  const { name, email, password, fcmToken } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
  if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Input non valido' });
  if (name.length < 3 || password.length < 6) return res.status(400).json({ error: 'Nome o password troppo corti' });
  // Blocco nomi vietati
  const forbidden = [
    // ...existing code...
  ];
  const lowerName = name.toLowerCase();
  if (forbidden.some(word => lowerName.includes(word))) {
    return res.status(400).json({ error: 'Nome utente non consentito.' });
  }
  if (await findUserByName(name)) return res.status(409).json({ error: 'Nome profilo già registrato' });
  if (await findUserByEmail(email)) return res.status(409).json({ error: 'Email già registrata' });
  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { name, email, password: hashedPassword, id: name };
  // Salva fcmToken solo se è una stringa valida (non finto, non null, non vuoto)
  if (typeof fcmToken === 'string' && fcmToken && fcmToken.length > 30 && !fcmToken.startsWith('TEST_TOKEN')) {
    console.log('[DEBUG] /register received fcmToken valido per', name, '->', fcmToken);
    newUser.fcmToken = fcmToken;
  } else {
    console.log('[DEBUG] /register fcmToken ignorato (non valido):', fcmToken);
  }
  await insertUser(newUser);
  console.log('[DEBUG] /register inserted user', name, { id: newUser.id, fcmToken: newUser.fcmToken ? 'SET' : 'NULL' });
  const { password: _, ...userSafe } = newUser;
  res.json({ user: userSafe });
});

// ===== ROUTE RANKING =====
app.get('/ranking/global', async (req, res) => {
  try {
    const ranking = await loadRankingData();
    const marketData = await loadMarketData(); // Carica i dati del mercato per i crediti
    
    // Prendi tutti gli utenti registrati
    const db = await connectMongo();
    const users = await db.collection('users').find({}).toArray();
    const allUsernames = Array.from(new Set([
      ...users.map(u => u.name),
      ...Object.keys(ranking.global)
    ]));
    const arr = allUsernames.map(username => {
      const stats = ranking.global[username] || { punti: 0, golFatti: 0, golSubiti: 0, diffReti: 0 };
      const userMarket = marketData.users[username];
      const credits = userMarket ? userMarket.credits || 0 : 0; // Crediti reali dal mercato
      
      return { username, ...stats, credits };
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
    const marketData = await loadMarketData(); // Carica i dati del mercato per i crediti
    
    const weekData = ranking.weekly[week] || {};
    const arr = Object.entries(weekData).map(([username, stats]) => {
      const userMarket = marketData.users[username];
      const credits = userMarket ? userMarket.credits || 0 : 0; // Crediti reali dal mercato
      
      return { username, ...stats, credits };
    });
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
  // === LOGICA AGGIORNAMENTO VALORI SQUADRE IN BASE ALLA CLASSIFICA REALE ===
  async function aggiornaValoriSquadreMercato() {
    console.log('🔄 Inizio aggiornamento valori squadre...');
    
    let marketData = await loadMarketData();
    if (!marketData.squadre) marketData.squadre = {};
    
    // Valori base per tutte le squadre
    const LEAGUE_CODES = ['SA', 'PL', 'PD', 'BL1', 'FL1'];
    const LEAGUE_NAMES = {
      'SA': 'Serie A',
      'PL': 'Premier League',
      'PD': 'LaLiga',
      'BL1': 'Bundesliga',
      'FL1': 'Ligue 1'
    };
    
    for (const code of LEAGUE_CODES) {
      try {
        const res = await fetch(`${FOOTBALL_DATA_API}/${code}/standings?season=2025`, {
          headers: { 'X-Auth-Token': FOOTBALL_DATA_TOKEN }
        });
        
        if (!res.ok) continue;
        
        const data = await res.json();
        const standings = data.standings[0]?.table || [];
        
        // Assegna valori in base alla posizione: 1° = 20, 2° = 19, ... 20° = 1
        standings.forEach((team, idx) => {
          const teamName = normalizeTeamName(team.team.name);
          const valore = Math.max(20 - idx, 1); // Minimo 1 credito
          
          if (!marketData.squadre[teamName]) marketData.squadre[teamName] = {};
          marketData.squadre[teamName].valoreAcquisto = valore;
          marketData.squadre[teamName].posizione = idx + 1;
          marketData.squadre[teamName].lega = LEAGUE_NAMES[code];
        });
        
        console.log(`✅ ${LEAGUE_NAMES[code]}: ${standings.length} squadre aggiornate`);
      } catch (e) {
        console.error(`❌ Errore aggiornamento ${LEAGUE_NAMES[code]}:`, e.message);
      }
    }
    
    await saveMarketData(marketData);
    console.log('✅ Valori squadre aggiornati in base alle classifiche reali!');
  }

// === LOGICA LIMITI CAMBI ===
const MAX_CAMBI_PER_WINDOW = 6;

app.post('/market/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const { credits, selected, confirmed, vendita, acquisto, valoreVendita, valoreAcquisto } = req.body;
    if (!username) return res.status(400).json({ error: 'Username mancante' });
    let data = await loadMarketData();
    
    // --- CONTROLLO NUOVA FINESTRA: resetta confirmed se mercato aperto ---
    if (data.users[username] && data.users[username].confirmed && isMercatoOpen()) {
      const now = new Date();
      const currentWindow = mercatoWindows.find(win => new Date(win.start) <= now && now <= new Date(win.end));
      if (currentWindow && data.users[username].lastWindow !== currentWindow.start) {
        data.users[username].confirmed = false;
        data.users[username].cambi = 0;
        data.users[username].lastWindow = currentWindow.start;
      }
    }
    
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
      data.users[username].confirmed = false; // Sblocca il mercato per la nuova finestra
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
    let userData = data.users[username];
    if (!userData) return res.status(404).json({ error: 'Nessun dato mercato per questo utente' });
    
    // SBLOCCO FORZATO: Se il mercato è aperto, sblocca SEMPRE
    if (isMercatoOpen()) {
      const now = new Date();
      const currentWindow = mercatoWindows.find(win => new Date(win.start) <= now && now <= new Date(win.end));
      if (currentWindow) {
        // Se è una nuova finestra O se confirmed è true, sblocca
        if (userData.lastWindow !== currentWindow.start || userData.confirmed) {
          userData.confirmed = false;
          userData.cambi = 0;
          userData.lastWindow = currentWindow.start;
          // Aggiorna i valori delle squadre in base alla classifica attuale
          await aggiornaValoriSquadreMercato();
          data.users[username] = userData;
          await saveMarketData(data);
          console.log(`✅ MERCATO SBLOCCATO per ${username} - Finestra: ${currentWindow.start}`);
          console.log(`📊 Valori squadre aggiornati in base alla classifica`);
        }
      }
    }
    
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
      await saveUserProfilePic(username, uploadRes.secure_url);
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
  console.log('[DEBUG] /register-fcm-token body:', req.body);
  const db = await connectMongo();
  const upd = await db.collection('users').updateOne(
    { name: username },
    { $set: { fcmToken } },
    { upsert: true }
  );
  console.log('[DEBUG] /register-fcm-token updateOne result for', username, upd.result || upd);
  res.json({ ok: true });
});

app.get('/profile-pic/:username', async (req, res) => {
  const username = req.params.username;
  const url = await getUserProfilePic(username);
  if (url) {
    res.json({ url });
  } else {
    res.status(404).json({ error: 'Foto profilo non trovata' });
  }
});

// ===== ROUTE FORMAZIONE: Salva la formazione confermata per utente =====
// Funzioni formazione su MongoDB
async function loadFormationData() {
  const db = await connectMongo();
  const formations = await db.collection('formations').find({}).toArray();
  const result = {};
  for (const f of formations) {
    result[f.userId] = {
      starters: f.starters,
      confirmed: f.confirmed,
      timestamp: f.timestamp,
      week: f.week
    };
  }
  return result;
}

async function saveFormationData(userId, formationObj) {
  const db = await connectMongo();
  await db.collection('formations').updateOne(
    { userId: userId },
    { 
      $set: { 
        userId: userId,
        starters: formationObj.starters,
        confirmed: formationObj.confirmed,
        timestamp: formationObj.timestamp,
        week: formationObj.week
      } 
    },
    { upsert: true }
  );
}

async function getFormationByUser(userId) {
  const db = await connectMongo();
  return await db.collection('formations').findOne({ userId: userId });
}

// Salva la formazione solo se non già confermata per il turno
app.post('/formation/:userId', async (req, res) => {
  try {
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
    // Salva formazione su MongoDB
    const formationObj = {
      starters,
      confirmed: true,
      timestamp: new Date().toISOString(),
      week: next.week
    };
    await saveFormationData(userId, formationObj);
    console.log(`✅ Formazione salvata su MongoDB per ${userId} - Settimana ${next.week}`);
    res.json({ ok: true, starters, week: next.week });
  } catch (error) {
    console.error('Errore salvataggio formazione:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
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
app.get('/formation/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const formation = await getFormationByUser(userId);
    if (!formation) {
      return res.status(404).json({ error: 'Nessuna formazione confermata trovata' });
    }
    res.json({
      starters: formation.starters,
      confirmed: formation.confirmed,
      timestamp: formation.timestamp,
      week: formation.week
    });
  } catch (error) {
    console.error('Errore recupero formazione:', error);
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// ===== SISTEMA AUTOMAZIONE RISULTATI REALI =====
// Mappa nomi vecchi/italiani usati nel MongoDB → nomi ufficiali API
const OLD_NAMES_MAPPING = {
  // Serie A - Nomi vecchi/abbreviati
  'Napoli': 'SSC Napoli',
  'Inter': 'FC Internazionale Milano',
  'Inter Milan': 'FC Internazionale Milano',
  'Atalanta': 'Atalanta BC',
  'Juventus': 'Juventus FC',
  'Juve': 'Juventus FC',
  'Roma': 'AS Roma',
  'Fiorentina': 'ACF Fiorentina',
  'Lazio': 'SS Lazio',
  'Milan': 'AC Milan',
  'Bologna': 'Bologna FC 1909',
  'Como': 'Como 1907',
  'Torino': 'Torino FC',
  'Udinese': 'Udinese Calcio',
  'Genoa': 'Genoa CFC',
  'Verona': 'Hellas Verona FC',
  'Hellas Verona': 'Hellas Verona FC',
  'Cagliari': 'Cagliari Calcio',
  'Parma': 'Parma Calcio 1913',
  'Lecce': 'US Lecce',
  'Sassuolo': 'US Sassuolo Calcio',
  // Premier League - Nomi vecchi/abbreviati
  'Liverpool': 'Liverpool FC',
  'Arsenal': 'Arsenal FC',
  'Manchester City': 'Manchester City FC',
  'Man City': 'Manchester City FC',
  'Chelsea': 'Chelsea FC',
  'Newcastle': 'Newcastle United FC',
  'Newcastle United': 'Newcastle United FC',
  'Aston Villa': 'Aston Villa FC',
  'Nottingham Forest': 'Nottingham Forest FC',
  'Brighton': 'Brighton & Hove Albion FC',
  'Bournemouth': 'AFC Bournemouth',
  'Brentford': 'Brentford FC',
  'Fulham': 'Fulham FC',
  'Crystal Palace': 'Crystal Palace FC',
  'Everton': 'Everton FC',
  'West Ham': 'West Ham United FC',
  'West Ham Utd': 'West Ham United FC',
  'West Ham United': 'West Ham United FC',
  'Manchester United': 'Manchester United FC',
  'Man United': 'Manchester United FC',
  'Wolves': 'Wolverhampton Wanderers FC',
  'Wolverhampton': 'Wolverhampton Wanderers FC',
  'Tottenham': 'Tottenham Hotspur FC',
  'Spurs': 'Tottenham Hotspur FC',
  'Burnley': 'Burnley FC',
  'Leeds': 'Leeds United FC',
  'Leeds United': 'Leeds United FC',
  'Sunderland': 'Sunderland AFC',
  // LaLiga - Nomi vecchi/italiani/abbreviati
  'Barcelona': 'FC Barcelona',
  'Barcellona': 'FC Barcelona',
  'Barça': 'FC Barcelona',
  'Real Madrid': 'Real Madrid CF',
  'Atletico Madrid': 'Atlético de Madrid',
  'Atletico': 'Atlético de Madrid',
  'Athletic Bilbao': 'Athletic Club',
  'Athletic': 'Athletic Club',
  'Villarreal': 'Villarreal CF',
  'Betis': 'Real Betis Balompié',
  'Real Betis': 'Real Betis Balompié',
  'Celta': 'RC Celta de Vigo',
  'Celta Vigo': 'RC Celta de Vigo',
  'Rayo Vallecano': 'Rayo Vallecano de Madrid',
  'Osasuna': 'CA Osasuna',
  'Mallorca': 'RCD Mallorca',
  'Real Sociedad': 'Real Sociedad de Fútbol',
  'Valencia': 'Valencia CF',
  'Getafe': 'Getafe CF',
  'Espanyol': 'RCD Espanyol de Barcelona',
  'Alaves': 'Deportivo Alavés',
  'Alavés': 'Deportivo Alavés',
  'Girona': 'Girona FC',
  'Sevilla': 'Sevilla FC',
  'Siviglia': 'Sevilla FC',
  'Oviedo': 'Real Oviedo',
  'Elche': 'Elche CF',
  'Levante': 'Levante UD',
  // Bundesliga - Nomi vecchi/italiani/abbreviati
  'Bayern': 'FC Bayern München',
  'Bayern Munich': 'FC Bayern München',
  'Bayern Monaco': 'FC Bayern München',
  'Bayer Leverkusen': 'Bayer 04 Leverkusen',
  'Leverkusen': 'Bayer 04 Leverkusen',
  'Eintracht': 'Eintracht Frankfurt',
  'Frankfurt': 'Eintracht Frankfurt',
  'Dortmund': 'Borussia Dortmund',
  'Borussia Dortmund': 'Borussia Dortmund',
  'Freiburg': 'SC Freiburg',
  'Mainz': '1. FSV Mainz 05',
  'Leipzig': 'RB Leipzig',
  'RB Leipzig': 'RB Leipzig',
  'Werder Bremen': 'SV Werder Bremen',
  'Bremen': 'SV Werder Bremen',
  'Stuttgart': 'VfB Stuttgart',
  'Gladbach': 'Borussia Mönchengladbach',
  'Borussia Monchengladbach': 'Borussia Mönchengladbach',
  'Wolfsburg': 'VfL Wolfsburg',
  'Augsburg': 'FC Augsburg',
  'Union Berlin': '1. FC Union Berlin',
  'St Pauli': 'FC St. Pauli',
  'St. Pauli': 'FC St. Pauli',
  'Hoffenheim': 'TSG Hoffenheim',
  'Heidenheim': '1. FC Heidenheim',
  'Koln': '1. FC Köln',
  'Köln': '1. FC Köln',
  'Cologne': '1. FC Köln',
  'Hamburger SV': 'Hamburger SV',
  'Hamburg': 'Hamburger SV',
  // Ligue 1 - Nomi vecchi/italiani/abbreviati
  'PSG': 'Paris Saint-Germain FC',
  'Paris': 'Paris Saint-Germain FC',
  'Paris Saint-Germain': 'Paris Saint-Germain FC',
  'Marsiglia': 'Olympique de Marseille',
  'Marseille': 'Olympique de Marseille',
  'Monaco': 'AS Monaco FC',
  'Nice': 'OGC Nice',
  'Lille': 'Lille OSC',
  'Lyon': 'Olympique Lyonnais',
  'Lione': 'Olympique Lyonnais',
  'Strasbourg': 'RC Strasbourg Alsace',
  'Lens': 'Racing Club de Lens',
  'Brest': 'Stade Brestois 29',
  'Toulouse': 'Toulouse FC',
  'Auxerre': 'AJ Auxerre',
  'Rennes': 'Stade Rennais FC 1901',
  'Nantes': 'FC Nantes',
  'Angers': 'Angers SCO',
  'Le Havre': 'Le Havre AC',
  'Metz': 'FC Metz',
  'Lorient': 'FC Lorient',
  'Paris FC': 'Paris FC'
};

// Mappa squadre per normalizzare nomi tra API e app
// Questa mappa converte i nomi API ufficiali nei nomi usati dall'app
const TEAM_MAPPING = {
  // Serie A - Nomi ufficiali API
  'SSC Napoli': 'SSC Napoli',
  'FC Internazionale Milano': 'FC Internazionale Milano',
  'Atalanta BC': 'Atalanta BC',
  'Juventus FC': 'Juventus FC',
  'AS Roma': 'AS Roma',
  'ACF Fiorentina': 'ACF Fiorentina',
  'SS Lazio': 'SS Lazio',
  'AC Milan': 'AC Milan',
  'Bologna FC 1909': 'Bologna FC 1909',
  'Como 1907': 'Como 1907',
  'Torino FC': 'Torino FC',
  'Udinese Calcio': 'Udinese Calcio',
  'Genoa CFC': 'Genoa CFC',
  'Hellas Verona FC': 'Hellas Verona FC',
  'Cagliari Calcio': 'Cagliari Calcio',
  'Parma Calcio 1913': 'Parma Calcio 1913',
  'US Lecce': 'US Lecce',
  'US Sassuolo Calcio': 'US Sassuolo Calcio',
  'AC Pisa 1909': 'AC Pisa 1909',
  'US Cremonese': 'US Cremonese',
  // Premier League - Nomi ufficiali API
  'Liverpool FC': 'Liverpool FC',
  'Arsenal FC': 'Arsenal FC',
  'Manchester City FC': 'Manchester City FC',
  'Chelsea FC': 'Chelsea FC',
  'Newcastle United FC': 'Newcastle United FC',
  'Aston Villa FC': 'Aston Villa FC',
  'Nottingham Forest FC': 'Nottingham Forest FC',
  'Brighton & Hove Albion FC': 'Brighton & Hove Albion FC',
  'AFC Bournemouth': 'AFC Bournemouth',
  'Brentford FC': 'Brentford FC',
  'Fulham FC': 'Fulham FC',
  'Crystal Palace FC': 'Crystal Palace FC',
  'Everton FC': 'Everton FC',
  'West Ham United FC': 'West Ham United FC',
  'Manchester United FC': 'Manchester United FC',
  'Wolverhampton Wanderers FC': 'Wolverhampton Wanderers FC',
  'Tottenham Hotspur FC': 'Tottenham Hotspur FC',
  'Burnley FC': 'Burnley FC',
  'Leeds United FC': 'Leeds United FC',
  'Sunderland AFC': 'Sunderland AFC',
  // LaLiga - Nomi ufficiali API
  'FC Barcelona': 'FC Barcelona',
  'Real Madrid CF': 'Real Madrid CF',
  'Atlético de Madrid': 'Atlético de Madrid',
  'Athletic Club': 'Athletic Club',
  'Villarreal CF': 'Villarreal CF',
  'Real Betis Balompié': 'Real Betis Balompié',
  'RC Celta de Vigo': 'RC Celta de Vigo',
  'Rayo Vallecano de Madrid': 'Rayo Vallecano de Madrid',
  'CA Osasuna': 'CA Osasuna',
  'RCD Mallorca': 'RCD Mallorca',
  'Real Sociedad de Fútbol': 'Real Sociedad de Fútbol',
  'Valencia CF': 'Valencia CF',
  'Getafe CF': 'Getafe CF',
  'RCD Espanyol de Barcelona': 'RCD Espanyol de Barcelona',
  'Deportivo Alavés': 'Deportivo Alavés',
  'Girona FC': 'Girona FC',
  'Sevilla FC': 'Sevilla FC',
  'Real Oviedo': 'Real Oviedo',
  'Elche CF': 'Elche CF',
  'Levante UD': 'Levante UD',
  // Bundesliga - Nomi ufficiali API
  'FC Bayern München': 'FC Bayern München',
  'Bayer 04 Leverkusen': 'Bayer 04 Leverkusen',
  'Eintracht Frankfurt': 'Eintracht Frankfurt',
  'Borussia Dortmund': 'Borussia Dortmund',
  'SC Freiburg': 'SC Freiburg',
  '1. FSV Mainz 05': '1. FSV Mainz 05',
  'RB Leipzig': 'RB Leipzig',
  'SV Werder Bremen': 'SV Werder Bremen',
  'VfB Stuttgart': 'VfB Stuttgart',
  'Borussia Mönchengladbach': 'Borussia Mönchengladbach',
  'VfL Wolfsburg': 'VfL Wolfsburg',
  'FC Augsburg': 'FC Augsburg',
  '1. FC Union Berlin': '1. FC Union Berlin',
  'FC St. Pauli': 'FC St. Pauli',
  'TSG Hoffenheim': 'TSG Hoffenheim',
  '1. FC Heidenheim': '1. FC Heidenheim',
  '1. FC Köln': '1. FC Köln',
  'Hamburger SV': 'Hamburger SV',
  // Ligue 1 - Nomi ufficiali API
  'Paris Saint-Germain FC': 'Paris Saint-Germain FC',
  'Olympique de Marseille': 'Olympique de Marseille',
  'AS Monaco FC': 'AS Monaco FC',
  'OGC Nice': 'OGC Nice',
  'Lille OSC': 'Lille OSC',
  'Olympique Lyonnais': 'Olympique Lyonnais',
  'RC Strasbourg Alsace': 'RC Strasbourg Alsace',
  'Racing Club de Lens': 'Racing Club de Lens',
  'Stade Brestois 29': 'Stade Brestois 29',
  'Toulouse FC': 'Toulouse FC',
  'AJ Auxerre': 'AJ Auxerre',
  'Stade Rennais FC 1901': 'Stade Rennais FC 1901',
  'FC Nantes': 'FC Nantes',
  'Angers SCO': 'Angers SCO',
  'Le Havre AC': 'Le Havre AC',
  'FC Metz': 'FC Metz',
  'FC Lorient': 'FC Lorient',
  'Paris FC': 'Paris FC'
};

// Funzione per normalizzare nomi squadre
function normalizeTeamName(apiName) {
  // Normalizzazione base: rimuove accenti, spazi e caratteri speciali
  const normalize = s => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/gi, '');
  
  // Prima prova match esatto
  if (TEAM_MAPPING[apiName]) return TEAM_MAPPING[apiName];
  
  // Poi prova match normalizzato
  const normalizedInput = normalize(apiName);
  for (const [key, value] of Object.entries(TEAM_MAPPING)) {
    if (normalize(key) === normalizedInput) return value;
  }
  
  // Fallback: restituisce il nome originale
  return apiName;
}

// Funzione per recuperare risultati di una giornata specifica
async function fetchMatchResults(league, matchday, matchdayMapping = null) {
  const code = FOOTBALL_DATA_CODES[league];
  if (!code) return {};
  
  // Usa il mapping fornito o fallback a matchday
  const actualMatchday = matchdayMapping?.[league] || matchday;
  const season = LEAGUE_SEASONS[league] || 2025;
  
  try {
    console.log(`🔄 Recupero risultati ${league} - Settimana ${matchday} → Giornata ${actualMatchday} (Stagione ${season})`);
    const res = await fetch(`${FOOTBALL_DATA_API}/${code}/matches?matchday=${actualMatchday}&season=${season}`, {
      headers: { 'X-Auth-Token': FOOTBALL_DATA_TOKEN }
    });
    
    if (!res.ok) {
      console.error(`❌ Errore API ${league}:`, res.status);
      return {};
    }
    
    const data = await res.json();
    const results = {};
    
    for (const match of data.matches || []) {
      if (match.status !== 'FINISHED') continue;
      
      const homeTeam = normalizeTeamName(match.homeTeam.name);
      const awayTeam = normalizeTeamName(match.awayTeam.name);
      const homeScore = match.score.fullTime.home;
      const awayScore = match.score.fullTime.away;
      
      // Determina esito per squadra di casa
      let homeResult, awayResult;
      if (homeScore > awayScore) {
        homeResult = { esito: 'W', gf: homeScore, gs: awayScore };
        awayResult = { esito: 'L', gf: awayScore, gs: homeScore };
      } else if (homeScore < awayScore) {
        homeResult = { esito: 'L', gf: homeScore, gs: awayScore };
        awayResult = { esito: 'W', gf: awayScore, gs: homeScore };
      } else {
        homeResult = { esito: 'D', gf: homeScore, gs: awayScore };
        awayResult = { esito: 'D', gf: awayScore, gs: homeScore };
      }
      
      results[homeTeam] = homeResult;
      results[awayTeam] = awayResult;
    }
    
    console.log(`✅ ${league} - Giornata ${matchday}: ${Object.keys(results).length} squadre`);
    return results;
  } catch (e) {
    console.error(`❌ Errore fetch risultati ${league}:`, e.message);
    return {};
  }
}

// Funzione principale per aggiornare automaticamente il ranking
async function updateRankingWithRealResults(week) {
  console.log(`🚀 INIZIO aggiornamento automatico ranking - Settimana ${week}`);
  
  try {
    // 1. Trova automaticamente l'ultima giornata finita per ogni lega
    console.log(`🔍 Cerco ultima giornata finita per ogni lega...`);
    const matchdayMapping = await getLastFinishedMatchdayForAllLeagues();
    
    // 2. Recupera tutti i risultati da tutte le leghe
    const allResults = {};
    for (const league of Object.keys(FOOTBALL_DATA_CODES)) {
      const leagueResults = await fetchMatchResults(league, week, matchdayMapping);
      Object.assign(allResults, leagueResults);
    }
    
    if (Object.keys(allResults).length === 0) {
      console.log(`⚠️ Nessun risultato trovato per la settimana ${week}`);
      return { updated: 0, error: 'Nessun risultato disponibile' };
    }
    
    console.log(`📊 Risultati recuperati: ${Object.keys(allResults).length} squadre`);
    
    // 3. Carica tutte le formazioni confermate da MongoDB per questa settimana
    const db = await connectMongo();
    const formations = await db.collection('formations').find({ 
      confirmed: true,
      week: week 
    }).toArray();
    
    console.log(`📋 Trovate ${formations.length} formazioni confermate per la settimana ${week}`);
    
    const ranking = await loadRankingData();
    
    let updatedUsers = 0;
    
    // 3. Aggiorna il ranking per ogni utente che ha inviato la formazione
    for (const formation of formations) {
      if (!formation.confirmed || !formation.starters) continue;
      const userId = formation.userId;
      
      console.log(`🔄 Calcolo punti per ${userId}...`);
      
      // Calcola punti per le squadre schierate
      const giornata = calcolaPunteggioGiornata(formation.starters, allResults);
      
      // Aggiorna ranking settimanale
      if (!ranking.weekly[week]) ranking.weekly[week] = {};
      ranking.weekly[week][userId] = giornata;
      
      // Aggiorna ranking globale
      if (!ranking.global[userId]) {
        ranking.global[userId] = { punti: 0, golFatti: 0, golSubiti: 0, diffReti: 0 };
      }
      
      ranking.global[userId].punti += giornata.punti;
      ranking.global[userId].golFatti += giornata.golFatti;
      ranking.global[userId].golSubiti += giornata.golSubiti;
      ranking.global[userId].diffReti = ranking.global[userId].golFatti - ranking.global[userId].golSubiti;
      
      updatedUsers++;
      console.log(`✅ ${userId}: ${giornata.punti} punti (${giornata.golFatti}-${giornata.golSubiti})`);
    }
    
    // 4. Salva il ranking aggiornato
    await saveRankingData(ranking);
    
    console.log(`🎉 COMPLETATO aggiornamento automatico: ${updatedUsers} utenti aggiornati`);
    
    return { 
      updated: updatedUsers, 
      week: week,
      totalResults: Object.keys(allResults).length,
      results: allResults 
    };
    
  } catch (error) {
    console.error(`❌ ERRORE aggiornamento automatico:`, error.message);
    throw error;
  }
}

// ===== ROUTE ADMIN: AGGIORNAMENTO AUTOMATICO RANKING =====
app.post('/admin/update-ranking-auto/:week', async (req, res) => {
  try {
    const week = parseInt(req.params.week);
    if (!week || week < 1 || week > 38) {
      return res.status(400).json({ error: 'Settimana non valida (1-38)' });
    }
    
    const result = await updateRankingWithRealResults(week);
    res.json({ 
      ok: true, 
      message: `Ranking aggiornato automaticamente per la settimana ${week}`,
      ...result 
    });
  } catch (e) {
    console.error('Errore aggiornamento automatico:', e.message);
    res.status(500).json({ 
      error: 'Errore aggiornamento automatico', 
      details: e.message 
    });
  }
});

// Endpoint di test per salvare formazione con settimana specifica (SOLO PER TEST)
app.post('/admin/formation-test/:userId/:week', async (req, res) => {
  try {
    const userId = req.params.userId;
    const week = parseInt(req.params.week);
    const { starters } = req.body;
    
    if (!Array.isArray(starters) || starters.length !== 11) {
      return res.status(400).json({ error: 'Serve array di 11 squadre' });
    }
    
    const formationObj = {
      starters,
      confirmed: true,
      timestamp: new Date().toISOString(),
      week: week
    };
    
    await saveFormationData(userId, formationObj);
    console.log(`✅ [TEST] Formazione salvata per ${userId} - Settimana ${week}`);
    res.json({ ok: true, starters, week });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== ROUTE ADMIN: VERIFICA RISULTATI DISPONIBILI =====
app.get('/admin/check-results/:league/:week', async (req, res) => {
  try {
    const { league, week } = req.params;
    const results = await fetchMatchResults(league, parseInt(week));
    
    res.json({
      league,
      week: parseInt(week),
      available: Object.keys(results).length > 0,
      totalMatches: Object.keys(results).length / 2, // Diviso 2 perché ogni partita ha 2 squadre
      results
    });
  } catch (e) {
    res.status(500).json({ error: 'Errore verifica risultati', details: e.message });
  }
});

// ===== ROUTE ADMIN: PULIZIA DATI UTENTE =====
app.post('/admin/clean-user-data/:username', async (req, res) => {
  try {
    const username = req.params.username;
    if (!username) {
      return res.status(400).json({ error: 'Username mancante' });
    }
    
    console.log(`🧹 PULIZIA DATI per utente: ${username}`);
    
    // 1. Pulisci ranking globale e settimanale
    const ranking = await loadRankingData();
    
    // Rimuovi da ranking globale
    if (ranking.global[username]) {
      delete ranking.global[username];
      console.log(`✅ Rimosso ${username} da ranking globale`);
    }
    
    // Rimuovi da tutti i ranking settimanali
    let weeksCleaned = 0;
    for (const week in ranking.weekly) {
      if (ranking.weekly[week][username]) {
        delete ranking.weekly[week][username];
        weeksCleaned++;
      }
    }
    console.log(`✅ Rimosso ${username} da ${weeksCleaned} ranking settimanali`);
    
    // Salva ranking pulito
    await saveRankingData(ranking);
    
    // 2. Pulisci dati mercato
    const marketData = await loadMarketData();
    if (marketData.users[username]) {
      delete marketData.users[username];
      await saveMarketData(marketData);
      console.log(`✅ Rimosso ${username} da dati mercato`);
    }
    
    // 3. Pulisci formazioni
    const formationData = loadFormationData();
    if (formationData[username]) {
      delete formationData[username];
      saveFormationData(formationData);
      console.log(`✅ Rimosso ${username} da formazioni`);
    }
    
    console.log(`🎉 PULIZIA COMPLETATA per ${username}`);
    
    res.json({ 
      ok: true, 
      message: `Dati utente ${username} completamente puliti`,
      cleaned: {
        ranking: true,
        weeksCleared: weeksCleaned,
        market: !!marketData.users[username],
        formations: !!formationData[username]
      }
    });
  } catch (e) {
    console.error('Errore pulizia dati utente:', e.message);
    res.status(500).json({ 
      error: 'Errore pulizia dati utente', 
      details: e.message 
    });
  }
});

// ===== ROUTE ADMIN: AGGIORNAMENTO AUTOMATICO SETTIMANALE =====
app.post('/admin/auto-update-current-week', async (req, res) => {
  try {
    // Trova la settimana comune corrente
    const next = getNextCommonWeekAndFirstMatch();
    if (!next) {
      return res.status(400).json({ error: 'Nessuna settimana comune disponibile' });
    }
    
    // Verifica se è passato abbastanza tempo dalla prima partita (es. 2 ore)
    const now = new Date();
    const timeSinceFirstMatch = now - next.firstMatch;
    const twoHours = 2 * 60 * 60 * 1000;
    
    if (timeSinceFirstMatch < twoHours) {
      return res.status(400).json({ 
        error: 'Troppo presto per aggiornare i risultati',
        firstMatch: next.firstMatch,
        waitUntil: new Date(next.firstMatch.getTime() + twoHours)
      });
    }
    
    const result = await updateRankingWithRealResults(next.week);
    res.json({ 
      ok: true, 
      message: `Ranking aggiornato automaticamente per la settimana corrente ${next.week}`,
      ...result 
    });
  } catch (e) {
    res.status(500).json({ 
      error: 'Errore aggiornamento automatico settimana corrente', 
      details: e.message 
    });
  }
});

// ===== ROUTE ADMIN: MIGRAZIONE FOTO PROFILO DA FILE A DB =====
app.post('/admin/migrate-profile-pics', async (req, res) => {
  try {
    console.log('🔄 INIZIO migrazione foto profilo da file a MongoDB...');
    
    // Controlla se il file esiste
    if (!fs.existsSync(USERS_FILE)) {
      return res.json({ ok: true, message: 'Nessun file da migrare', migrated: 0 });
    }
    
    // Leggi il file delle foto profilo
    const fileData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    const users = fileData.users || {};
    
    let migrated = 0;
    const db = await connectMongo();
    
    // Migra ogni foto nel database
    for (const [username, photoUrl] of Object.entries(users)) {
      try {
        await db.collection('users').updateOne(
          { name: username },
          { $set: { profilePicUrl: photoUrl } }
        );
        console.log(`✅ Migrata foto per ${username}`);
        migrated++;
      } catch (err) {
        console.error(`❌ Errore migrazione ${username}:`, err.message);
      }
    }
    
    console.log(`🎉 MIGRAZIONE COMPLETATA: ${migrated} foto migrate`);
    
    res.json({ 
      ok: true, 
      message: `${migrated} foto profilo migrate con successo nel database`,
      migrated,
      totalFound: Object.keys(users).length
    });
  } catch (e) {
    console.error('❌ Errore migrazione foto profilo:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===== ROUTE ADMIN: PULISCI UTENTE COMPLETAMENTE =====
app.post('/admin/emergency-clean/:username', async (req, res) => {
  try {
    const username = req.params.username;
    console.log(`🚨 PULIZIA EMERGENZA per: ${username}`);
    
    let cleaned = {
      ranking_global: false,
      ranking_weekly: 0,
      market: false,
      formations: false
    };
    
    // 1. PULISCI RANKING (global + weekly)
    const ranking = await loadRankingData();
    
    // Rimuovi da global
    if (ranking.global && ranking.global[username]) {
      delete ranking.global[username];
      cleaned.ranking_global = true;
      console.log(`✅ Rimosso ${username} da ranking globale`);
    }
    
    // Rimuovi da tutti i weekly
    if (ranking.weekly) {
      for (const week in ranking.weekly) {
        if (ranking.weekly[week] && ranking.weekly[week][username]) {
          delete ranking.weekly[week][username];
          cleaned.ranking_weekly++;
        }
      }
      console.log(`✅ Rimosso ${username} da ${cleaned.ranking_weekly} ranking settimanali`);
    }
    
    // Salva ranking pulito
    await saveRankingData(ranking);
    
    // 2. PULISCI MARKET
    const marketData = await loadMarketData();
    if (marketData.users && marketData.users[username]) {
      delete marketData.users[username];
      cleaned.market = true;
      console.log(`✅ Rimosso ${username} da market`);
    }
    await saveMarketData(marketData);
    
    // 3. PULISCI FORMATIONS (file locale)
    const formationData = loadFormationData();
    if (formationData[username]) {
      delete formationData[username];
      cleaned.formations = true;
      console.log(`✅ Rimosso ${username} da formations`);
    }
    saveFormationData(formationData);
    
    console.log(`🎉 PULIZIA EMERGENZA COMPLETATA per ${username}`);
    
    res.json({ 
      ok: true, 
      message: `${username} completamente rimosso da ranking e market!`,
      cleaned
    });
  } catch (e) {
    console.error('Errore pulizia emergenza:', e.message);
    res.status(500).json({ error: e.message });
  }
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
  
  // Deduplicazione: raggruppa per token FCM unico per evitare duplicati
  const uniqueTokens = new Map();
  for (const user of users) {
    if (user.fcmToken && !uniqueTokens.has(user.fcmToken)) {
      uniqueTokens.set(user.fcmToken, user);
    }
  }
  
  // Notifiche formazione
  for (const n of formationNotifications) {
    if (Math.abs(n.date - now) < 60 * 1000) {
      for (const [token, user] of uniqueTokens) {
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
          await sendPushNotification(token, title, body, { type: n.type });
        }
      }
    }
  }
  // Notifiche mercato
  for (const n of mercatoNotifications) {
    if (Math.abs(n.date - now) < 60 * 1000) {
      for (const [token, user] of uniqueTokens) {
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
          await sendPushNotification(token, title, body, { type: n.type });
        }
      }
    }
  }
}

// ===== ENDPOINT DEBUG FORMAZIONI =====
app.get('/admin/formations/debug', async (req, res) => {
  try {
    const db = await connectMongo();
    const formations = await db.collection('formations').find({}).toArray();
    
    const summary = formations.map(f => ({
      username: f.username,
      week: f.week,
      confirmed: f.confirmed,
      numSquadre: f.squadre ? f.squadre.length : 0,
      timestamp: f.timestamp
    }));
    
    res.json({
      total: formations.length,
      formations: summary
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== AUTOMAZIONE RANKING SETTIMANALE =====
async function autoUpdateRankingRoutine() {
  try {
    const next = getNextCommonWeekAndFirstMatch();
    if (!next) return;
    
    const now = new Date();
    const timeSinceFirstMatch = now - next.firstMatch;
    const twoHours = 2 * 60 * 60 * 1000;
    
    // Aggiorna automaticamente 2 ore dopo la prima partita della settimana
    if (timeSinceFirstMatch >= twoHours && timeSinceFirstMatch <= twoHours + 60000) { // Finestra di 1 minuto
      console.log('🚀 AVVIO aggiornamento automatico ranking settimanale...');
      try {
        const result = await updateRankingWithRealResults(next.week);
        console.log(`✅ Ranking aggiornato automaticamente: ${result.updated} utenti`);
        
        // Invia notifica a tutti gli utenti sui nuovi risultati
        const db = await connectMongo();
        const users = await db.collection('users').find({ fcmToken: { $exists: true } }).toArray();
        
        const uniqueTokens = new Map();
        for (const user of users) {
          if (user.fcmToken && !uniqueTokens.has(user.fcmToken)) {
            uniqueTokens.set(user.fcmToken, user);
          }
        }
        
        for (const [token, user] of uniqueTokens) {
          try {
            await sendPushNotification(
              token,
              '📊 Classifica Aggiornata!',
              `I risultati della settimana ${next.week} sono disponibili. Controlla la tua posizione!`,
              { type: 'ranking_updated', week: next.week.toString() }
            );
          } catch (e) {
            console.error(`❌ Errore notifica ranking a ${user.name}:`, e.message);
          }
        }
        
      } catch (error) {
        console.error('❌ Errore aggiornamento automatico ranking:', error.message);
      }
    }
  } catch (error) {
    console.error('❌ Errore routine automazione ranking:', error.message);
  }
}

// Routine notifiche ogni minuto
setInterval(notificationRoutine, 60 * 1000);

// Routine aggiornamento ranking automatico ogni 5 minuti
setInterval(autoUpdateRankingRoutine, 5 * 60 * 1000);

const PORT = process.env.PORT || 1000;
app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
  console.log('🤖 Sistema automazione ranking attivato');
});


