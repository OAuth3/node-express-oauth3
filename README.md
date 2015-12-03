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

Standalone Example
==================

This example will create dynamic routes for all providers

  * `/api/oauth3/authorization_redirect/:providerUri`
  * `/api/oauth3/authorization_redirect?provider_uri=:providerUri`

There will also be an internal route for code and token handling:

  * `/api/oauth3/authorization_code_callback`

```javascript
'use strict';

var PromiseA = require('bluebird').Promise;

// Note that "App", "Client", and "Consumer" are different names for the same thing
// One site's docs will say "App ID" another will say "Consumer Public Key", etc - but they're the same.

// For sites that don't support OAuth3 automatic registration
// you can provide the pre-registered OAuth2 client id and secret here
var providerConfig = {
  'example.com:example.org': {
    id: 'my-app-id'
  , secret: 'my-app-secret'
  }
, 'example.com:facebook.com': {
    id: 'other-app-id'
  , secret: 'other-app-secret'
  , "directives": {
      "authorization_dialog": {
        "method": "GET"
      , "url": "https://www.facebook.com/dialog/oauth"
      }
    , "access_token": {
        "method": "GET"
      , "url": "https://graph.facebook.com/oauth/access_token"
      , "params": {
          "redirect_uri": "https://oauth3.org" + "/api/oauth3/authorization_code_callback/facebook.com"
        }
      }
    , "profile": {
        "method": "GET"
      , "url": "https://graph.facebook.com/me"
      }
    , "authn_scope": ""
    }
  }
};

var DirectiveStore = {
  getAsync:  function (hostname, providerUri) { return PromiseA.resolve(providerConfig[hostname + ':' + providerUri]); }
, setAsync: function (hostname, providerUri, registration) { providerConfig[hostname + ':' + providerUri] = registration; return PromiseA.resolve(); }
, pruneAsync: function () { /* remove expired and stale */ }
};
var TempStore = {
  _db: {}
, getAsync:  function (key) { return PromiseA.resolve(TempStare._db[key]); }
, setAsync: function (key, value) { TempStore._db[key] = value; return PromiseA.resolve(); }
, pruneAsync: function () { /* ... */ }
};

OAuth3.create(app, DirectiveStore, TempStore, {
  domain: "https://example-api.org"
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
    + encodeURIComponent('https://consumer-fronted.com/oauth3.html'
        + '?provider_uri=' + encodeURIComponent('https://provider-api.com')
      )
  + '&scope=' + encodeURIComponent(requestedScope)
  + '&state=' + toHex(crypto.getRandomValues(new Uint8Array(16)))
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

License
=======

(MIT OR Apache-2.0)

See LICENSE
