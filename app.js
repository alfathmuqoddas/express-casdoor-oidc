const express = require("express");
const session = require("express-session");
const passport = require("passport");
const { Issuer, Strategy } = require("openid-client");

const app = express();

app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true })
);
app.use(passport.initialize());
app.use(passport.session());

const CASDOOR_ISSUER_URL = "http://localhost:8000";
const CLIENT_ID = "471814f8dec174e83a9b";
const CLIENT_SECRET = "1d5eed54053811b9154e5e26c36342cb692bf830";
const REDIRECT_URI = "http://localhost:3000/auth/casdoor/callback";
const CUSTOM_AUTHORIZATION_ENDPOINT =
  "http://localhost:8000/login/oauth/authorize";

Issuer.discover(CASDOOR_ISSUER_URL).then((casdoorIssuer) => {
  const client = new casdoorIssuer.Client({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uris: [REDIRECT_URI],
    response_types: ["code"],
    authorization_endpoint: CUSTOM_AUTHORIZATION_ENDPOINT,
  });

  passport.use(
    "casdoor",
    new Strategy(
      {
        client,
        params: {
          redirect_uri: REDIRECT_URI,
          scope: "profile",
        },
      },
      (tokenSet, userinfo, done) => {
        return done(null, userinfo);
      }
    )
  );
});

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

function requireLogin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  next();
}

app.get("/", (req, res) => {
  res.send("<a href='/login'>Log In with OAuth 2.0 Provider </a>");
});

app.get("/login", passport.authenticate("casdoor"));

app.get(
  "/auth/casdoor/callback",
  passport.authenticate("casdoor", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/profile");
  }
);

app.get("/profile", requireLogin, (req, res) => {
  res.json(req.user);
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
