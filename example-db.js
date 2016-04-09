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
      id: '1689773534599654'
    , secret: '24394783fe17b50429a20369d8272d55'
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

  // Note that you don't need to provide any urls or client ids
  // You don't need separate routes for different providers either
  DirectiveStore = {
    getAsync:  function (providerUri) {
      return PromiseA.resolve(providerConfig[providerUri]);
    }
  , setAsync: function (providerUri, registration) {
      providerConfig[providerUri] = registration;

      return PromiseA.resolve();
    }
    /*
  , pruneAsync: function () {
    }
    */
  };


