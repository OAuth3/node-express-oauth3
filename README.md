passport-oauth3
===============

Node.js / ExpressJS / PassportJS Strategy for OAuth2 / OAuth3 providers


OAuth3 (aka OAuthn) is a 100% backwards compatible, more strict subset of OAuth2.
It easier to implement, test, debug.
It also has the advantages of being federated, delegated, cacheable, and more private.

Unlike OAuth2, OAuth3 does not require any knowledge of the implementation details
of either party.

Also, OAuth3 may use JavaScript to perform many client-side functions,
including issuing tokens.

Example
=======

```javascript
'use strict';

var Passport = require('passport').Passport;
var passport = new Passport();
var PromiseA = require('bluebird').Promise;

var OAuth3Strategy = require('passport-oauth3').Strategy;
// These strings are arbitrary
var authorizationRedirect = "/api/oauth3/authorization_redirect";
var authorizationCodeCallback = "/api/oauth3/authorization_code_callback";
var accessTokenCallback = "/api/oauth3/access_token_callback";

// Note that "App", "Client", and "Consumer" are different names for the same thing
// One site's docs will say "App ID" another will say "Consumer Public Key", etc - but they're the same.
//
// For sites that don't support OAuth3 automatic registration
// you can provide the pre-registered OAuth2 client id and secret here
var providerConfig = {
  'example.org': {
    id: 'my-app-id'
  , secret: 'my-app-secret'
  }
, 'facebook.com': {
    id: 'other-app-id'
  , secret: 'other-app-secret'
  }
};

//
// Example for getting and setting registration information
// (OAuth3 can automatically register app id / app secret)
//
function stripLeadingProtocolAndTrailingSlash(uri) {
  return uri.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
}

//
// Automatic Registration
//
// For services that support automatic registration, 
// tell the service your security policy.
//
// DRAFT (this is not yet spec'd)
function getRegistrationOptions(providerUri) {
  return {
    allowed_domains: [ "https://awesome.com", "https://partner-site.com" ]
  , allowed_ips: [ "10.0.0.0/24", "10.100.100.100" ]
  , allowed_redirects: [ "https://awesome.com/oauth3.html", "https://api.awesome.com/oauth3/" ]
  };
}

function getRegistrationValues(providerUri) {
  var key = stripLeadingProtocolAndTrailingSlash(providerUri);

  return PromiseA.resolve(providerConfig[key]);
}

function setRegistrationValues(providerUri, registration) {
  // registration is not yet implemented
  var key = stripLeadingProtocolAndTrailingSlash(providerUri);

  providerConfig[key] = registration;

  return PromiseA.resolve();
}

//
// This will be used by passport to set `req.user`
//
function getUserFromToken(req, providerUri, info, params) {
  // info = { accessToken, refreshToken, appScopedId, grantedScopes, profile }
  return PromiseA.resolve({ user: info.profile, info: info });
}

// Note that you don't need to provide any urls or client ids
// You don't need separate routes for different providers either
passport.use('oauth3-strategy-1', new OAuth3Strategy({
  providerCallback: getRegistrationValues 
, registrationCallback: setRegistrationValues
, authorizationCodeCallbackUrl: "https://my-awesome-consumer.com" + authorizationCodeCallback 
, accessTokenCallbackUrl: "https://my-awesome-consumer.com" + authorizationCodeCallback 
}
, getUserFromToken
));

app.get(authorizationRedirect, passport.authenticate('oauth3-strategy-1'));

app.get(authorizationCodeCallback, passport.authenticate('oauth3-strategy-1'));

// This looks a little convoluted only because passport doesn't have a method
// for passing some of the necessary parameters back to the caller and there's
// no way to wrap it inside of OAuth3Strategy#authenticate
function handleOauth3Response(req, res, next, err, user, info, status) {
  // info = { accessToken, refreshToken, grantedScopes, appScopedId, profile }
  // req.query = { provider_uri, code, state }
  // user = { ... } // profile

  var params = { 'provider_uri': req.query.provider_uri };
  var challenge;

  if (err) {
    params.error = err.message;
    params.error_description = err.message;
  }

  if (!user) {
    challenge = info; // info is overloaded as challenge on error
    return PromiseA.reject(params);
  }

  return new PromiseA(function (resolve, reject) {
    req.login({ profile: user, info: info }, function (err) {
      if (err) {
        params.error = err.message;
        params.error_description = err.message;
        reject(params);
        return;
      }

      // NOTE: refreshToken does *not* go to the browser
      params.access_token = info.accessToken;
      params.expires_at = info.expiresAt;
      params.app_scoped_id = info.appScopedId;
      params.granted_scopes = info.grantedScopes;

      resolve(params);
    });
  });
}

app.get(accessTokenCallback, function (req, res, next) {
  passport.authenticate('oauth3-strategy-1', function (err, user, info, status) {
    var querystring = require('querystring');

    handleOauth3Response(req, res, next, err, user, info, status).then(function (params) {
      res.redirect('/oauth-close.html?' + querystring.stringify(params));
    }, function (err) {
      var params;
      if (err.error_description) {
        params = err;
        res.redirect('/oauth-close.html?' + querystring.stringify(params));
      } else {
        res.end("Error: " + err.message);
      }
    });
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
