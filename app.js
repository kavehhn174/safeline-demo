'use strict';

const path = require('path');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_NAME = process.env.SITE_NAME || 'SafeLine Demo Site';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// The app sits behind SafeLine (a reverse proxy), so trust X-Forwarded-* headers.
app.set('trust proxy', true);
app.disable('x-powered-by');

app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Request log: anything SafeLine blocks should NOT show up here.
// That is the easiest way to prove the WAF is working during the demo.
app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    const line = [
      new Date().toISOString(),
      req.ip,
      req.method,
      JSON.stringify(req.originalUrl.slice(0, 200)),
      res.statusCode,
      `${Date.now() - started}ms`,
    ].join(' ');
    console.log(line);
  });
  next();
});

app.use((req, res, next) => {
  res.locals.siteName = SITE_NAME;
  res.locals.currentPath = req.path;
  res.locals.clientIp = req.ip;
  next();
});

// ---- In-memory data (no database, nothing to exploit) ----------------------
const guestbook = [
  { name: 'Alice', message: 'Great demo site!', at: new Date().toISOString() },
];
const MAX_ENTRIES = 50;

const files = {
  'readme.txt': 'This is a harmless sample file served from memory.',
  'report.txt': 'Quarterly report: everything is fine.',
};

const users = {
  1: { id: 1, name: 'Alice', role: 'user' },
  2: { id: 2, name: 'Bob', role: 'user' },
  3: { id: 3, name: 'Admin', role: 'admin' },
};

// ---- Pages -----------------------------------------------------------------
app.get('/', (req, res) => {
  res.render('index', { title: 'Home' });
});

// Reflects the query back (escaped by EJS <%= %>), a typical XSS / SQLi target.
app.get('/search', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : '';
  res.render('search', { title: 'Search', q, results: q ? [] : null });
});

// Fake login: always fails. Good for SQLi / brute-force tests.
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null, username: '' });
});

app.post('/login', (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.slice(0, 100) : '';
  res.status(401).render('login', {
    title: 'Login',
    error: 'Invalid username or password.',
    username,
  });
});

app.get('/guestbook', (req, res) => {
  res.render('guestbook', { title: 'Guestbook', entries: guestbook.slice().reverse() });
});

app.post('/guestbook', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 50) || 'Anonymous';
  const message = String(req.body.message || '').trim().slice(0, 300);
  if (message) {
    guestbook.push({ name, message, at: new Date().toISOString() });
    if (guestbook.length > MAX_ENTRIES) guestbook.shift();
  }
  res.redirect('/guestbook');
});

// File "download": only looks up a fixed in-memory map, never touches the disk.
app.get('/files', (req, res) => {
  const name = typeof req.query.name === 'string' ? req.query.name.slice(0, 200) : '';
  const hasOwn = Object.prototype.hasOwnProperty.call(files, name);
  res.status(name && !hasOwn ? 404 : 200).render('files', {
    title: 'Files',
    names: Object.keys(files),
    name,
    content: hasOwn ? files[name] : null,
    notFound: Boolean(name) && !hasOwn,
  });
});

// ---- JSON API --------------------------------------------------------------
app.get('/api/users', (req, res) => {
  const id = String(req.query.id || '');
  if (!id) return res.json(Object.values(users));
  const user = Object.prototype.hasOwnProperty.call(users, id) ? users[id] : null;
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.json(user);
});

app.post('/api/echo', (req, res) => {
  res.json({ received: req.body });
});

app.get('/healthz', (req, res) => {
  res.type('text').send('ok');
});

// ---- Errors ----------------------------------------------------------------
app.use((req, res) => {
  res.status(404).render('error', { title: 'Not found', code: 404, message: 'Page not found.' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  res.status(status).render('error', {
    title: 'Error',
    code: status,
    message: status === 500 ? 'Something went wrong.' : err.message,
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`${SITE_NAME} listening on port ${PORT}`);
});
