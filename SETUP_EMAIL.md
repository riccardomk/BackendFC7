# Configurazione Reset Password con Email

## Setup Email (Gmail)

Per inviare email di reset password, devi configurare le credenziali Gmail:

### Passo 1: Genera Password App Gmail
1. Vai su https://myaccount.google.com/security
2. Attiva **"Verifica in due passaggi"** (se non è già attiva)
3. Cerca **"Password per le app"** o **"App passwords"**
4. Seleziona:
   - App: **Altro (nome personalizzato)**
   - Nome: `FantaFC Backend`
5. Clicca **Genera**
6. Copia la password generata (16 caratteri)

### Passo 2: Configura Variabili d'Ambiente

Se stai usando **Render** o **Heroku**, aggiungi queste variabili d'ambiente:

```
EMAIL_USER=tuaemail@gmail.com
EMAIL_PASS=lapasswordgeneratadagmail
```

Se stai testando **localmente**, crea un file `.env` nella cartella `backend/`:

```bash
cd backend
echo EMAIL_USER=tuaemail@gmail.com >> .env
echo EMAIL_PASS=lapasswordgeneratadagmail >> .env
```

### Passo 3: Installa dotenv (se non già fatto)

```bash
cd backend
npm install dotenv
```

### Passo 4: Carica le variabili in server.js

Aggiungi all'inizio di `server.js` (se non c'è già):

```javascript
import dotenv from 'dotenv';
dotenv.config();
```

## Come Funziona il Reset Password

1. **Utente richiede reset**: L'utente inserisce il nome profilo nel campo login e clicca "Password dimenticata?"
2. **Backend genera token**: Il server crea un token sicuro (32 caratteri) valido per 30 minuti
3. **Email inviata**: Nodemailer invia un'email con il link `fantafc://reset-password?token=...`
4. **Utente clicca link**: Il deep link apre l'app nella schermata ResetPasswordScreen
5. **Nuova password**: L'utente inserisce la nuova password e conferma
6. **Password aggiornata**: Il server aggiorna la password e rimuove il token

## Test Locale

Per testare localmente senza deploy:

```bash
cd backend
node server.js
```

Poi testa con:
```bash
curl -X POST http://localhost:3000/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"name":"tuonomeutente"}'
```

Dovresti ricevere un'email con il link di reset.

## Provider Email Alternativi

### Outlook/Hotmail
```javascript
service: 'hotmail'
```

### Yahoo
```javascript
service: 'yahoo'
```

### SendGrid (consigliato per produzione)
```javascript
host: 'smtp.sendgrid.net',
port: 587,
auth: {
  user: 'apikey',
  pass: process.env.SENDGRID_API_KEY
}
```

## Troubleshooting

### Email non arriva
- Verifica che EMAIL_USER e EMAIL_PASS siano corrette
- Controlla la cartella spam
- Verifica che la "Verifica in due passaggi" sia attiva su Gmail
- Assicurati di usare una "Password per app" e NON la password Gmail normale

### Token scaduto
- I token sono validi per 30 minuti
- Richiedi un nuovo reset se è scaduto

### Deep link non funziona
- Verifica che AndroidManifest.xml abbia l'intent-filter con scheme="fantafc"
- Ricompila l'app: `cd android && ./gradlew clean && cd .. && npx react-native run-android`
