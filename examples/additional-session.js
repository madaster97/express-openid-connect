const express = require('express');
const { auth } = require('../');
const jose = require('jose');
const session = require('express-session');

// Match express-session default store
const MemoryStore = require('memorystore')(auth);

/** Assumed workflow, the user will not be given a session ID until one of the following occurs:
 * 1. They do a pre-login action like a shopping cart choice
 * 2. They complete a login flow
 *
 * In addition, logging out will:
 * 1. Delete the current session, including the shopping cart, from the store
 * 2. Leave the user without a session ID
 */

/**
 * Same user logs in again
 * 1. Update the existing session (keep the old ID)
 * 2. Save the update so subsequent requests get the new data
 */
async function reLogin(req) {
  req.session.loginCount++;
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}
/**
 * New user logs into blank session
 * 1. Check for pre-login session, save off for later
 * 2. Always regenerate for new login
 * 3. Always save after handling login
 *
 * We'll always regenerate
 */
async function newLogin(req, cart) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) {
        reject(err);
      } else {
        req.session.loginCount = 1;
        if (cart) {
          req.session.cart = cart;
        }
        req.session.save((err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      }
    });
  });
}
// // New user logs in over old user
async function replaceLogin(req) {
  // Can treat it as new login with no cart
  return newLogin(req);
}
// Logout user
async function logout(req) {
  return new Promise((resolve, reject) => {
    req.destroy((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

const app = express();

// Call first, so afterCallback can set session
app.use(
  session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
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
    afterCallback: async (req, res, session) => {
      const { sub: newSub } = jose.JWT.decode(session.id_token);
      if (req.oidc.isAuthenticated()) {
        if (req.oidc.user.sub === newSub) {
          // The same user logged in again, just update existing session
          await reLogin(req);
        } else {
          // A different user logged in, logout old user, regenerate ID and assign new session
          await replaceLogin(req);
        }
      } else {
        // A new user is replacing an anonymous session
        // regenerate the session, which is good practice to help
        // guard against forms of session fixation
        const { cart } = req.session; // Destructure to make a copy
        await newLogin(req, cart);
      }
      return session;
    },
    session: {
      store: new MemoryStore({
        checkPeriod: 24 * 60 * 1000,
      }),
    },
  })
);

app.get('/app-logout', async (req, res) => {
  await logout(req);
  res.redirect('/');
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
