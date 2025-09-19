import express from 'express';
import session from 'express-session';
import fetch from 'node-fetch';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const GUILD_ID = process.env.GUILD_ID;
const ALLOWED_ROLES = process.env.ALLOWED_ROLES.split(',');

app.use(session({ secret: 'discordsecret', resave: false, saveUninitialized: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware sprawdzający rolę
async function checkRole(req, res, next) {
  if (!req.session.access_token) return res.redirect('/auth/discord');

  try {
    const memberRes = await fetch(`https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`, {
      headers: { Authorization: `Bearer ${req.session.access_token}` }
    });
    const member = await memberRes.json();
    const roles = member.roles || [];
    const hasAccess = roles.some(r => ALLOWED_ROLES.includes(r));
    if (!hasAccess) return res.status(403).send('Brak dostępu – nie masz wymaganej roli.');
    next();
  } catch (err) {
    console.error(err);
    res.status(500).send('Błąd serwera');
  }
}

// Autoryzacja Discord
app.get('/auth/discord', (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify guilds.members.read`;
  res.redirect(url);
});

app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  const data = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI
  });

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      body: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const tokenData = await tokenRes.json();
    req.session.access_token = tokenData.access_token;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Błąd logowania Discord');
  }
});

// Strona główna – wymaga odpowiedniej roli
app.get('/', checkRole, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
