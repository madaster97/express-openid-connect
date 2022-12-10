const express = require('express');
const { auth } = require('../');
const jose = require('jose');
const session = require('express-session');

// Match express-session default store
const MemoryStore = require('memorystore')(auth);

const app = express();

// Call first, so afterCallback can set session
app.use(
  session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(
  auth({
    routes: {
      // Have SDK redirect to you after logout
      postLogoutRedirect: '/app-logout',
    },
    authorizationParams: {
      // Force re-auth. Switch user to demonstrate issue
      prompt: 'login',
    },
    authRequired: false,
    afterCallback: (req, res, session) => {
      const { sub: newSub } = jose.JWT.decode(session.id_token);
      return new Promise((resolve, reject) => {
        if (req.oidc.isAuthenticated()) {
          if (req.oidc.user.sub === newSub) {
            // The same user logged in again, just update existing session
            req.session.loginCount++;
            resolve(session);
          } else {
            // A different user logged in, logout old user, regenerate ID and assign new session
            req.session.loginCount = null;
            req.session.save(function (err) {
              if (err) {
                reject(err);
              } else {
                // regenerate the session, which is good practice to help
                // guard against forms of session fixation
                req.session.regenerate(function (err) {
                  if (err) {
                    reject(err);
                  } else {
                    req.session.loginCount = 1;
                    resolve(session);
                  }
                });
              }
            });
          }
        } else {
          // A new user is replacing an anonymous session
          // regenerate the session, which is good practice to help
          // guard against forms of session fixation
          req.session.regenerate(function (err) {
            if (err) {
              reject(err);
            } else {
              req.session.loginCount = 1;
              // save the session before redirection to ensure page
              // load does not happen before session is saved
              req.session.save(function (err) {
                if (err) {
                  reject(err);
                } else {
                  resolve(session);
                }
              });
            }
          });
        }
      });
    },
    session: {
      store: new MemoryStore({
        checkPeriod: 24 * 60 * 1000,
      }),
    },
  })
);

app.get('/app-logout', (req, res, next) => {
  req.session.loginCount = null;
  req.session.save(function (err) {
    if (err) next(err);

    // regenerate the session, which is good practice to help
    // guard against forms of session fixation
    req.session.regenerate(function (err) {
      if (err) next(err);
      res.redirect('/');
    });
  });
});

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(
      `You are logged in as ${req.oidc.user.sub},
            and have logged in ${req.session.loginCount} times.
            <br/>
            You can <a href="login">login</a> again or <a href="logout">logout</a>.
            <br/>
            Your session ID is ${req.session.id}`
    );
  } else {
    res.send(
      `You are not logged in, and have session ${JSON.stringify(
        req.session
      )}. Please <a href="login">login</a> to continue
      <br/>
            Your session ID is ${req.session.id}`
    );
  }
});

module.exports = app;
