const express = require('express');
const axios = require('axios');
const session = require('cookie-session');
const path = require('path');

const app = express();

// -------------------- KONFIG --------------------
const CLIENT_ID = '1418613573399216148';
const CLIENT_SECRET = '6S-4M-uL547bzAfvPjDtV8dN8t7FES_y';
const REDIRECT_URI = 'https://admstronaunimc.netlify.app/'; 
const GUILD_ID = '1169683173970550904';
const ALLOWED_ROLES = ['1170358299221295104']; // tablica nawet dla jednej rangi
// ------------------------------------------------

app.use(session({
    name: 'discord-auth-session',
    keys: ['supersecretkey'],
    maxAge: 24 * 60 * 60 * 1000
}));

// Strona startowa - od razu przekierowanie do Discord OAuth
app.get('/', (req, res) => {
    if(req.session.user && req.session.roles){
        const hasAccess = req.session.roles.some(role => ALLOWED_ROLES.includes(role));
        if(hasAccess){
            res.sendFile(path.join(__dirname, 'index.html'));
            return;
        }
    }
    const redirect = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify guilds.members.read`;
    res.redirect(redirect);
});

// Callback po autoryzacji
app.get('/auth/discord/callback', async (req, res) => {
    const code = req.query.code;
    if(!code) return res.send('Błąd autoryzacji');

    try {
        const params = new URLSearchParams();
        params.append('client_id', CLIENT_ID);
        params.append('client_secret', CLIENT_SECRET);
        params.append('grant_type', 'authorization_code');
        params.append('code', code);
        params.append('redirect_uri', REDIRECT_URI);

        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', params.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const accessToken = tokenResponse.data.access_token;

        // Dane użytkownika
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });
        const user = userResponse.data;

        // Pobranie ról na serwerze
        const memberResponse = await axios.get(`https://discord.com/api/users/@me/guilds/${GUILD_ID}/member`, {
            headers: { Authorization: `Bearer ${accessToken}` }
        }).catch(() => null);

        const roles = memberResponse?.data?.roles || [];
        req.session.user = user;
        req.session.roles = roles.map(r => r.name ? r.name : r);

        const hasAccess = roles.some(role => ALLOWED_ROLES.includes(role.name || role));
        if(hasAccess){
            res.redirect('/');
        } else {
            res.send('<h2>Nie masz uprawnień do tej strony</h2>');
        }

    } catch(err) {
        console.error(err);
        res.send('Błąd autoryzacji Discord');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server działa na porcie ${PORT}`));
