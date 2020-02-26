var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require("mongoose");
var bcrypt = require('bcrypt-nodejs');
var expressSession = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var dotenv = require('dotenv');
dotenv.config();

require('./models');

var User = mongoose.model('User');
var Quote = mongoose.model('Quote');
mongoose.connect(process.env.URL_DB,{ useNewUrlParser: true , useUnifiedTopology: true });

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
  secret: process.env.SESSION_SECRET
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use('signin',new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
  },function(email,password,next) {
  User.findOne({
    email: email
  },function (err, user) {
    if(err) return next(err);
    if(user) return next({message: "C'è gia un account con questa email"});

    let newUser = new User({
      email: email,
      passwordHash: bcrypt.hashSync(password,bcrypt.genSaltSync(10)),
      name: ""
    });

    newUser.save(function(err) {
      next(err,newUser);
    });
  });
}));

passport.use(new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
},function(email,password,next) {
  User.findOne({
    email: email
  },function(err,user) {
    if(err) return next(err);
    if(!user || !bcrypt.compareSync(password, user.passwordHash)){
      return next({message:"email o password sbagliati"})
    }
    next(null, user)
  })
}));

passport.serializeUser(function (user,next) {
  console.log("serialize");
  next(null,user._id)
});

passport.deserializeUser(function (id,next) {
  console.log("deserialize");
  User.findById(id, function (err,user) {
    next(err,user);
  })
});

app.get('/', function (req,res,next) {
  res.render('index')
});

app.get('/main',function (req,res,next) {
  if(req.session.gate === undefined){
    return next({message: "Effettua il login o la registrazione :("});
  }
  res.render('main' ,{n:req.session.n, q:"premi il tasto genera per ottenere una frase"})
});

app.get('/login', function (req,res,next) {
  res.render('login')
});

app.post('/login',
    passport.authenticate('local', { failureRedirect: '/login' }),
    function(req, res ,next) {
      u = User.findOne({email: req.body.email},function (err,user) {
          if(err) return next(err);
          console.log(user.name);
          req.session.n= user.name;
          req.session.gate = true;
          res.redirect('/main');
      });
});

app.post('/signup',
  passport.authenticate('signin', { failureRedirect: '/' }),
      function(req, res,next) {
        console.log(req.body.email);
        User.findOneAndUpdate({email: req.body.email}, {name: req.body.name}).exec();
        req.session.gate = true;
        req.session.n = req.body.name;
        res.redirect('/main');
});

app.post("/quotes",function (req,res,next) {
    // Get the count of all users
    Quote.count().exec(function (err, count) {

        // Get a random entry
        var random = Math.floor(Math.random() * count);

        // Again query all users but only fetch one offset by our random #
        Quote.findOne().skip(random).exec(
            function (err, result) {
                // Tada! random user
                console.log(result.quote);
                res.render("main",{n:req.session.n, q:result.quote})
            })
    })
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
