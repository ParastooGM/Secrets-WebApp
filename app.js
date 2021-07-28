require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const FacebookStrategy = require( 'passport-facebook' ).Strategy;
const findOrCreate = require("mongoose-findorcreate");
const flash = require('connect-flash');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true}));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
mongoose.connect("mongodb+srv://admin_parastoo:" + process.env.MDB_PASSWORD + "@cluster0.jlz7r.mongodb.net/userDB?retryWrites=true&w=majority", {useNewUrlParser: true ,  useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleID: String,
  facebookID: String,
  secret: String
});

//hashing and salting with passport
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

//creating local user strategy
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//creating google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://boiling-ravine-51903.herokuapp.com/auth/google/secrets",
    passReqToCallback   : true,
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

//creating facebook strategy
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "https://boiling-ravine-51903.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//routes
app.get("/", function(req, res){
  res.render("home");
});

//google OAuth
app.get("/auth/google",
    passport.authenticate('google', {
        scope: ["profile"]
    })
);

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login/flash'
}));

//facebook OAuth
  app.get("/auth/facebook",
      passport.authenticate('facebook', {
          scope: ["public_profile"]
      })
  );
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login/flash' }),
  function(req, res) {
    // Successful authentication
    res.redirect('/secrets');
  });

  app.get("/login", function(req, res){
    res.render("login", {message : req.flash('error')});
  });

//handelling unothorized requests.
  app.get('/login/flash', function(req, res){
    req.flash('error', 'Invalid Email Address or Password. Try Agin!')
    res.redirect('/login');
  });

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets" , function(req, res){
  //only allowed to see secrets if authenticated.
  if (req.isAuthenticated()){
    User.find({"secret" : {$ne: null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets" , {usersWithSecrets : foundUsers});
        }};
    });
  }else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
 req.logout();
 res.redirect("/");
});

app.get("/submit", function(req, res){
  //only allowed to submit secrets if authenticated.
  if (req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    }else{
      //local authentication
      passport.authenticate("local" , { failureRedirect: '/login/flash' })(req, res, function(){
        res.redirect("/secrets");
      });
    };
  })
});

app.post("/register", function(req, res){
  User.register({username: req.body.username} , req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      //local authentication
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  });
});

app.post("/submit" , function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if (err){
      console.log(err);
    }else{
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      };
    };
  });
});

let port = process.env.PORT;
if (port == null || port == ""){
  port = 3000
};

app.listen(port);
