passport-oauth3
===============

Node.js / ExpressJS / PassportJS Strategy for OAuth2 / OAuth3 providers


OAuth3 is a 100% backwards compatible, more strict subset of OAuth2.
It easier to implement, test, debug.
It also has the advantages of being federated, delegated, cacheable, and more private.

Unlike OAuth2, OAuth3 (aka OAuthN) does not require any knowledge of the
implementation details of either party.

Also, OAuth3 may use JavaScript 

Example
=======

```javascript
'use strict';

var Passport = require('passport').Passport;
var passport = new Passport();
var PromiseA = require('bluebird').Promise;
var OAuth3Strategy = require('passport-oauth3').Strategy;
var authorizationRedirect = "/api/oauth3/authorization_redirect";
var authorizationCodeCallback = "/api/oauth3/authorization_code_callback";
//var authorizationTokenCallback = "/api/oauth3/access_token_callback";

var providerConfig = {
  'example.org': {
    id: conf.id
  , secret: conf.secret
  }
};

passport.use('oauth3-strategy-1', new OAuth3Strategy({
  providerCallback: function (providerUri) {
    var key = providerUri.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');

    return PromiseA.resolve(providerConfig[key]);
  }
, registrationCallback: function (providerUri, conf) {
    // registration is not yet implemented
    var key = providerUri.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');

    // TODO enforce state to prevent false writes
    if (providerConfig[key] && !providerConfig[key].dynamic) {
      return PromiseA.reject("Attack! someone is trying to overwrite the config");
    }

    providerConfig[key] = conf;
    providerConfig[key].dynamic = true;

    return PromiseA.resolve();
  }
, callbackURL: conf.url + authorizationCodeCallback 
}
, function (req, providerUri, info, params) {
    // To keep the example simple, the user's LdsConnect profile is returned to
    // represent the logged-in user.  In a typical application, you would want
    // to associate the LdsConnect account with a user record in your database,
    // and return that user instead.
    // info = { accessToken, refreshToken, appScopedId, grantedScopes, profile }
    return PromiseA.resolve({ user: info.profile, info: info });
  }
));

app.get(authorizationRedirect, passport.authenticate('oauth3-strategy-1'));

app.get(authorizationCodeCallback, function (req, res, next) {
  // This route get hits the first time with the code and the second time with access_token

  passport.authenticate('oauth3-strategy-1', function (err, user, info, status) {
    // info = { accessToken, refreshToken, grantedScopes, appScopedId, profile }
    // req.query = { provider_uri, code, state }
    // user = { ... } // profile

    var querystring = require('querystring');
    var params = { 'provider_uri': req.query.provider_uri };
    var challenge;

    req.url = '/oauth-close.html?';

    if (err) {
      params.error = err.message;
      params.error_description = err.message;
    }

    if (user) {
      params.access_token = info.accessToken;
      params.app_scoped_id = info.appScopedId;
      params.granted_scopes = info.grantedScopes;
      // NOTE refreshToken should *not* go to the browser
    }

    req.url += querystring.stringify(params);

    res.redirect(req.url);
  })(req, res, next);
});
```

Authorization Dialog
-------------------

Imagine you're on the site "Wally's Widgets" and there's a button "Login with Foo".

When you click that button, one of two things should happen:

1. It goes to your server to perform a redirect for a code (a waste, if you ask me)
2. You open the dialog from your browser to request a token

This module applies to situation 1.

It seems like you could skip #1 and open the authorization dialog directly,
but since you're setting up a session on the server there's some session state
stuff that happens to... can't remember, gotta look back at the code... later...

### Server Redirect to Dialog

```javascript
var url = 'https://consumer-api.com/api/oauth3/authorization_redirect'
  + '?provider_uri=' + encodeURIComponent('https://provider-api.com')
  + '&scope=' + encodeURIComponent('login email phone')
  ;
```

'provider_uri' is used as part of the state as well as where it will find `oauth.json`.

### Browser Open Dialog

```
var myAppId = 'some-app-id';
var requestedScope = 'login email phone';
var url = 'https://provider-api.com/api/oauth3/authorization_dialog'
  + '?response_type=token'
  + '&client_id=' + myAppId
  + '&redirect_uri='
    + encodeURIComponent('https://consumer-fronted.com/oauth-close.html'
        + '?provider_uri=' + encodeURIComponent('https://provider-api.com')
      )
  + '&scope=' + encodeURIComponent(requestedScope)
  + '&state=' + Math.random().toString().replace(/^0./, '')
  ;
```

OAuth3 URLs
-----------

The provder's frontend *must* have a file `/oauth3.json`, which should be static.

It should be CORS enabled such that any web client can access it as well.

It should have a long `Expires` header and cached in the app manifest.

```javascript
var 'https://provider-fronteend.com/oauth3.json'
```

```javascript
{ "authorization_dialog": {
    "method": "GET"
  , "url": "https://provider-api.com/api/oauth3/authorization_dialog"
  }
, "access_token": {
    "method": "POST"
  , "url": "https://provider-api.com/api/oauth3/access_token"
  }
, "profile": {
    "method": "GET"
  , "url": "https://provider-api.com/api/oauth3/me"
  }
, "authn_scope": "me"
}
```

'authn_scope' defines the least possible scope required to authenticate
and get 'app_scoped_id'. 
