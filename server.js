if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

const configurePassport = require('./custom-passport-setup');
configurePassport(
  passport,
  email => usersDatabase.find(user => user.email === email),
  id => usersDatabase.find(user => user.id === id)
);

const usersDatabase = [];

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', ensureAuthenticated, (req, res) => {
  res.render('home.ejs', { username: req.user.name });
});

app.get('/login', ensureNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.post('/login', ensureNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/register', ensureNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', ensureNotAuthenticated, async (req, res) => {
  try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      usersDatabase.push({
          id: Date.now().toString(),
          name: req.body.name,
          email: req.body.email,
          password: hashedPassword
      });
      res.redirect('/login');
  } catch (error) {
      console.error(error);
      res.redirect('/register');
  }
});

app.delete('/logout', (req, res) => {
  req.logout((err) => {
      if (err) {
          console.error(err);
          return next(err);
      }
      res.redirect('/login');
  });
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
      return next();
  }
  res.redirect('/login');
}

function ensureNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
      return res.redirect('/');
  }
  next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
