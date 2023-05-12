require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const flash = require("connect-flash");
const User = require("./models/User");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.set("useCreateIndex", true);

//creating local user strategy
passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//creating google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      User.deleteOne({ username: profile.displayName }).then(() =>
        User.findOrCreate(
          { googleId: profile.id, username: profile.displayName },
          function (err, user) {
            return done(err, user);
          }
        )
      );
    }
  )
);

//creating facebook strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.APP_ID,
      clientSecret: process.env.APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.deleteOne({ username: profile.displayName }).then(() =>
        User.findOrCreate(
          { facebookId: profile.id, username: profile.displayName },
          function (err, user) {
            return cb(err, user);
          }
        )
      );
    }
  )
);

//routes
app.get("/", function (req, res) {
  res.render("home");
});

//google OAuth
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login/flash",
  })
);

//facebook OAuth
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", {
    scope: ["public_profile"],
  })
);

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login/flash" }),
  function (req, res) {
    // Successful authentication
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login", { message: req.flash("error") });
});

app.get("/register", function (req, res) {
  res.render("register", { message: req.flash("error_reg") });
});

//handelling unothorized requests.
app.get("/login/flash", function (req, res) {
  req.flash("error", "Invalid Email Address or Password. Try Agin!");
  res.redirect("/login");
});

app.get("/register/flash", function (req, res) {
  req.flash("error_reg", "Email already exists. Try Agin!");
  res.redirect("/register");
});

app.get("/secrets", function (req, res) {
  //only allowed to see secrets if authenticated.
  if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } }, function (err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", { usersWithSecrets: foundUsers });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/submit", function (req, res) {
  //only allowed to submit secrets if authenticated.
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      //local authentication
      passport.authenticate("local", { failureRedirect: "/login/flash" })(
        req,
        res,
        function () {
          res.redirect("/secrets");
        }
      );
    }
  });
});

app.post("/register", function (req, res) {
  if (User.find({ email: req.body.username })) {
    res.redirect("/register/flash");
  } else {
    User.register(
      { username: req.body.username },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log(err);
        } else {
          //local authentication
          passport.authenticate("local", {
            failureRedirect: "/register/flash",
          })(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("server started"));

module.exports = app;
