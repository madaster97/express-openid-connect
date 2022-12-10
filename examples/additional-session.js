const express = require('express');
const { auth } = require('../');
const session = require('express-session');

const app = express();

// Call first, so afterCallback can set session
app.use(session({ secret: 'keyboard cat' }));
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
      if (req.session.loginCount) {
        req.session.loginCount++;
      } else {
        req.session.loginCount = 1;
      }
      return session;
    },
  })
);

app.get('/app-logout', (req, res, next) => {
  req.session.destroy(function (err) {
    if (err) {
      next(err);
    } else {
      res.redirect('/');
    }
  });
});

app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.send(
      `You are logged in as ${req.oidc.user.sub},
            and have logged in ${req.session.loginCount} times.
            <br/>
            You can <a href="login">login</a> again or <a href="logout">logout</a>.`
    );
  } else {
    res.send(
      `You are not logged in, and have session ${JSON.stringify(
        req.session
      )}. Please <a href="login">login</a> to continue`
    );
  }
});

module.exports = app;
