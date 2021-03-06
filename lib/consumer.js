'use strict';

var Oauth3Consumer = module.exports = function () {};

/**
 * Module dependencies.
 */
var PromiseA = require('bluebird').Promise;
var crypto = require('crypto');

Oauth3Consumer.stripLeadingProtocolAndTrailingSlash = function (uri) {
  return uri.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
};

// Scenario:
//
// The browser loads lameapp.com/connect
// lameapp.com relies on oauth3.org for authorization_redirect
// lameapp.com/connect specifies lameapp.com as the client_uri
// (or lameapp.com specifies lameapp.com/connect)
//
// There needs to be a method to check that the page loaded in
// the browser should have access to the client it requested
//
// This needs to be checked again against the registration if
// client_id is used instead of client_uri
function laxUriMatch(clientUri, uris) {
  var parts = clientUri.split('/');
  var hostname = parts.shift().split('').reverse().join('') + '.';
  var pathname = parts.join('/').replace(/\/?$/, '/');

  // lax for right now
  function match(uri) {
    var parts2 = uri.split('/');
    // simpler to reverse and add '.' than to regex with borders
    var hostname2 = parts2.shift().split('').reverse().join('') + '.';
    var pathname2 = parts2.join('/').replace(/\/?$/, '/');

    if (0 === hostname.indexOf(hostname2) || 0 === hostname2.indexOf(hostname)) {
      if (0 === pathname.indexOf(pathname2) || 0 === pathname2.indexOf(pathname)) {
        return true;
      }
    }

    return false;
  }

  return [ 'referer', 'origin', 'hostname' ].some(function (key) {
    var uri = uris[key];

    return uri && match(uri);
  });
}

Oauth3Consumer._getOauthClient = function (self, req, providerUri, opts) {
  // TODO referer, host, etc
  var clientUri = opts.clientUri
    || Oauth3Consumer.stripLeadingProtocolAndTrailingSlash(opts.referer || opts.origin || opts.hostname);
  var normalProviderUri = Oauth3Consumer.stripLeadingProtocolAndTrailingSlash(providerUri);
  var err;

  if (opts.clientUri && !laxUriMatch(clientUri, opts)) {
    err = new Error("bad client uri in _getOauthClient");
    err.code = "E_BAD_CLIENT_URI";
    return PromiseA.reject(err);
  }

  //console.log('[DEBUG] _configStore.getAsync:');
  //console.log('        clientUri:', clientUri);
  //console.log('        normalProviderUri:', normalProviderUri);
  return self._configStore.getAsync(clientUri, normalProviderUri, opts).then(function (result) {
    //console.log('');
    //console.log('#####');
    //console.log('#####');
    //console.log('##### DEBUG post getAsync clientUri', clientUri);
    //console.log(result);
    //console.log('');
    //console.log('');
    var conf = result.registration || {};
    var directive = result.directive;
    //console.log('DEBUG directive.authorization_dialog.url', directive.authorization_dialog.url);

    // TODO automatic registration via directive.registration if conf.appId is missing

    var OAuth2 = require('oauth').OAuth2;
    var baseSite = ''; // leave as empty string so that Oauth3 (requires absolute URLs) can create its own
    var appId = conf.id
        || conf.appId || conf.appID
        || conf.consumerId || conf.consumerID
        || conf.clientId || conf.clientID
        || opts.clientId || opts.clientUri
        ;
    var appSecret = conf.secret || conf.clientSecret || conf.consumerSecret || conf.appSecret;

    if (!conf || !appSecret) {
      return PromiseA.reject({
        message: "Missing clientId or clientSecret for '" + providerUri + "': " + JSON.stringify(conf)
      , code: "E_NOT_REGISTERED"
      });
    }

    // TODO create instanceless Oauth3 module
    var oauth2 = PromiseA.promisifyAll(new OAuth2(
      appId
    , appSecret // TODO jwt ?
    , baseSite
    , directive.authorization_dialog.url
    , req.query.access_token_uri || req.query.token_uri || directive.access_token.url || conf.access_token
    , directive.http_headers
    ), { multiArgs: true });

    //console.log('DEBUG create oauth2 client with id and secret', clientUri);
    return { oauth2: oauth2, directive: directive };
  });
};

/**
 * `Strategy` constructor.
 *
 * The example-oauth2orize authentication strategy authenticates requests by delegating to
 * example-oauth2orize using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your example-oauth2orize application's client id
 *   - `clientSecret`  your example-oauth2orize application's client secret
 *   - `callbackURL`   URL to which example-oauth2orize will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new ExampleStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example-oauth2orize/callback'
 *       },
 *       function (accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Object} KeyValueStore
 * @api public
 */

Oauth3Consumer.create = function (TokenSigner, ConfigStore, KeyStore, kvStore, options) {
  if ('string' !== typeof options.authorizationCodeCallback || !/^\/\w/.test(options.authorizationCodeCallback)) {
    throw new Error(
      'options.authorizationCodeCallback should be a string'
    + ' in the format /api/oauth3/authorization_code_callback'
    + ' Note that /:providerUri will be appended as an optional variable and'
    + ' the ?provider_uri=example.com query search parameter will also be honored'
    );
  }
  if (options.domain && ('string' !== typeof options.domain || !/^https:\/\//.test(options.domain))) {
    throw new Error(
      'options.domain represents the API and should be a string'
    + ' in the format https://example.com'
    );
  }

  if ('function' !== typeof ConfigStore.getAsync) {
    throw new Error("Implement 'ConfigStore.getAsync' as 'function (hostnameId, providerUri) { return Promise.resolve({ id: 'id', secret: 'secret' }); }");
  }
  if (3 !== ConfigStore.getAsync.length) {
    throw new Error("'ConfigStore.getAsync' should accept exactly 3 parameters: tenantUri, providerUri, opts");
  }
  /*
  if ('function' !== typeof ConfigStore.setAsync) {
    throw new Error("Implement 'DS.setAsync' as 'function (hostnameId, providerUri, conf) { return Promise.resolve(); }");
  }
  if (3 !== ConfigStore.setAsync.length) {
    throw new Error("'DS.setAsync' should accept exactly 3 parameters: hostnameId, providerUri, config");
  }
  */

  var me = {};
  me.options = options;

  me._authorizationCodeCallback = options.authorizationCodeCallback;
  me._scopeSeparator = options.scopeSeparator || ' ';
  // in Oauth3 this is non-optional
  me._trustProxy = options.proxy;

  me._configStore = ConfigStore;

  me._kv = kvStore;
  me._signer = TokenSigner;
  if (!me._kv.getAsync) {
    me._kv = PromiseA.promisifyAll(kvStore, { multiArgs: false });
  }

  // XXX TODO XXX this need use the KV store
  me._directives = {};
  me._keyStore = KeyStore;

  return me;
};

function exchangeCodeForToken(self, req, oauth2, fullCallbackUrl, metaState/*, options*/) {
  var code = req.query.code;

  // TODO pull from directive
  var requestQuery = {};

  requestQuery.grant_type = 'authorization_code';
  requestQuery.redirect_uri = fullCallbackUrl;

  //console.log('DEBUG exchangeCodeForToken');
  //console.log(requestQuery);
  //console.log(code);
  return oauth2.getOAuthAccessTokenAsync(code, requestQuery).spread(function (accessToken, refreshToken, params) {
    //console.log('DEBUG exchangeCodeForToken accessToken');
    //console.log(accessToken);
    //console.log(refreshToken);
    //console.log(params);

    if (params.error) {
      params.browser_state = metaState.browserState;
      return params;
    }

    // TODO test for seconds away vs actual date
    if (parseInt(params.expires, 10)) {
      params.expires_in = params.expires_in || parseInt(params.expires, 10);
      params.expires_at = params.expires_at || Math.floor(new Date(Date.now() + (params.expires_in * 1000)).valueOf() / 1000);
    }

    params.access_token = params.access_token || accessToken;
    params.refresh_token = params.refresh_token || refreshToken;

    if (!params.access_token) {
      return {
        error: "E_UNKNOWN"
      , error_description: "No token was received and no error was given. We don't know why. It's not your fault."
      , error_uri: 'https://oauth3.org/docs/errors#' + 'E_UNKNOWN'
      , browser_state: metaState.browserState
      };
    }

    /* meta = { referer, host, scope, providerUri, browserState } */
    // https://tools.ietf.org/html/rfc6749#section-4.2.2
    /* params = { access_token, refresh_token, scope, state, token_type, expires_in, expires_at, expires (in) } */
    return self._signer.signAsync(metaState, params).then(function (tokens) {
      /* tokens = { access_token, refresh_token, scope, token_type, expires_in, expires_at } */
      /* {access,refresh}_token = { jti, iss, aud, sub, typ, iat, exp, data } */

      var resultkens = {
        session_access_token: tokens.access_token
      , session_refresh_token: tokens.refresh_token
      , session_expires_in: tokens.expires_in || params.expires_in
      , session_expires_at: tokens.expires_at || params.expires_at
      , session_provider_uri: req.hostname || req.headers.host || undefined

      , access_token: params.access_token
      , refresh_token: params.refresh_token
      , expires_in: params.expires_in
      , expires_at: params.expires_at

      , browser_state: metaState.browserState
      };

      return resultkens;
    });
  });
}

function parseRequestMeta(req, metaState) {
  var result;

  metaState = metaState || {};

  result = {
    clientId: req.query.client_id || req.query.clientId || metaState.clientId
  , clientUri: req.query.client_uri || req.query.clientUri || metaState.clientUri
  , tos: req.query.client_agree_tos || req.query.clientAgreeTos || metaState.tos
  , host: req.headers.host
  , hostname: (req.hostname || req.headers.host).split(':').shift()
  , origin: req.headers.origin
  , referer: req.headers.referer
  };
  result.clientUri = result.clientUri
      || Oauth3Consumer.stripLeadingProtocolAndTrailingSlash(result.referer || result.origin || result.hostname);

  return result;
}

function redirectToAuthorizationDialog(self, req, oauth2, providerUri, fullCallbackUrl, scope/*, directive*/) {
  //console.log('DEBUG redirectToAuthorizationDialog begin');
  var err;
  var params;
  var browserState;
  var serverState;
  var metaState;

  params = {}; // directive.authorization_code.params || {};
  params.response_type = 'code';
  params.redirect_uri = fullCallbackUrl;
  if (scope) {
    if (Array.isArray(scope)) { scope = scope.join(self._scopeSeparator); }
    params.scope = scope;
  }
  browserState = req.query.browser_state || req.query.state;

  if (!browserState) {
    err = new Error("the client MUST supply an &browser_state=<<random>> state when making the request."
     + " It does not need to be cryptographically random.");
    return PromiseA.reject(err);
  }

  serverState = crypto.randomBytes(32).toString('hex');

  metaState = parseRequestMeta(req);

  metaState.browserState = browserState;
  metaState.serverState = serverState;
  metaState.scope = params.scope;
  metaState.createdAt = Date.now();
  metaState.providerUri = providerUri;

  //console.log('create metaState');
  //console.log(metaState);

  if (metaState.clientUri && !laxUriMatch(metaState.clientUri, metaState)) {
    err = new Error("clientUri doesn't match referer or origin, even loosely");
    err.code = "E_BAD_CLIENT_URI";
    return PromiseA.reject(err);
  }

  return self._kv.setAsync(serverState, metaState).then(function () {
    params.state = serverState;

    return oauth2.getAuthorizeUrl(params);
  });
}

/**
 * Authenticate request by delegating to a service provider using OAuth 3.0.
 *
 * @param {Object} req
 * @api protected
 *
 * OAuth2 Example (for reference):
 *
 *    // options = { scope, callbackURL, mergeAuthorizationParams(options), state }
 *
 *    // Static Options
 *    rest.get(
 *      config.oauthPrefix + '/google/connect'
 *    , passport.authenticate(
 *        'google-oauth2'
 *        , { scope: ['https://www.googleapis.com/auth/plus.login'] } // options
 *      )
 *    );
 *
 *    // Dynamic Options
 *    rest.get(
 *      config.oauthPrefix + '/google/connect'
 *    , function (req, res) {
 *        passport.authenticate(
 *          'google-oauth2'
 *          , { scope: req.query.scope } // options
 *        )(req, res);
 *      }
 *    );
 */
Oauth3Consumer.authenticate = function (strategy, req, options) {
  if (!req.query.code) {
    return Oauth3Consumer.authorizationRedirect(strategy, req, options);
  } else {
    throw new Error("expected parameter 'code'");
  }
};

Oauth3Consumer.authorizationRedirect = function (strategy, req, options) {
  //console.log('DEBUG authorizationRedirect begin');
  options = options || {};
  var self = strategy;
  var providerUri = req.query.provider_uri || (req.params.providerUri && decodeURIComponent(req.params.providerUri));
  var tos = req.query.client_agree_tos || req.query.clientAgreeTos;
  options.tos = options.tos || tos;

  return Oauth3Consumer.authenticateHelper(strategy, req, providerUri, options).then(function (helpers) {
    var scope = req.query.scope || options.scope || helpers.directive.authn_scope;
    return redirectToAuthorizationDialog(self, req, helpers.oauth2, providerUri, helpers.callbackUrl, scope, helpers.directive);
  });
};

Oauth3Consumer.authorizationCodeCallback = function (conf, req, options) {
  //console.log('DEBUG authorizationCodeCallback begin');
  options = options || {};
  var serverState = req.query.state;

  return conf._kv.getAsync(serverState).then(function (metaState) {
    var err;

    if (!metaState) {
      err = new Error('Unable to verify authorization request state.');
      err.status = 403;
      // TODO err.code = 'E_NO_STATE';
      return PromiseA.reject(err);
    }

    if ('object' !== typeof metaState) {
      err = new Error('Unable to verify authorization request state.');
      err.status = 403;
      // TODO err.code = 'E_INVALID_STATE';
      return PromiseA.reject(err);
    }

    if (metaState.serverState !== req.query.state) {
      err = new Error('Invalid authorization request state.');
      err.status = 403;
      err.referer = metaState.referer;
      err.browserState = metaState.browserState;
      err.browser_state = metaState.browserState;
      err.state = metaState.browserState;
      // TODO err.code = 'E_INVALID_STATE';
      return PromiseA.reject(err);
    }

    options.metaState = metaState;
    return Oauth3Consumer.authenticateHelper(conf, req, metaState.providerUri, options).then(function (helpers) {
      // non-blocking async
      conf._kv.destroyAsync(serverState);
      // TODO run in cluster.isMaster every 5 minutes
      conf._kv.allAsync().then(function (all) {
        var now = Date.now();
        var item;

        function next() {
          item = all.pop();

          if (!item) {
            return;
          }

          if (now - item.createdAt > (15 * 60 * 1000)) {
            return conf._kv.destroyAsync(item.serverState).then(next);
          }

          return PromiseA.resolve().then(next);
        }

        return next();
      });
      return exchangeCodeForToken(conf, req, helpers.oauth2, helpers.callbackUrl, metaState, options);
    }).then(function (params) {
      var result = {};
      result.referer = metaState.referer;
      result.params = params;
      result.params.browser_state = metaState.browserState;
      return result;
    }, function (err) {
      err.referer = metaState.referer;
      err.browserState = metaState.browserState;
      err.browser_state = metaState.browserState;
      err.state = metaState.browserState;
      return PromiseA.reject(err);
    });
  });
};

Oauth3Consumer.authenticateHelper = function (self, req, providerUri, options) {
  //console.log('DEBUG authenticateHelper begin', providerUri);
  var err;
  // metaState is only passed in sometimes
  // also, I can't remember when it should take priority over req.headers and such
  var metaState = options.metaState || {};
  var AuthorizationError = require('./errors/authorizationerror');
  var metaData;

  if (!providerUri) {
    err = new Error("provider_uri must be passed as a url param, a query param, or related to the state param");
    err.code = "E_NO_PROVIDER_URI";
    return PromiseA.reject(err);
  }

  if (!/^(https?|spdy):\/\//.test(providerUri)) {
    providerUri = 'https://' + providerUri;
  }

  if (req.query.error) {
    if (req.query.error === 'access_denied') {
      err = new Error(req.query.error_description);
      err.code = req.query.error;
      err.uri = req.query.error_uri;
      return PromiseA.reject(err);
    } else {
      return PromiseA.resolve().then(function () {
        throw new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri);
      });
    }
  }

  metaData = parseRequestMeta(req, metaState);
  //console.log('[org.oauth3.consumer] auth helper metaData');
  //console.log(providerUri);
  //console.log(metaData);

  return Oauth3Consumer._getOauthClient(self, req, providerUri, metaData).then(function (info) {
    options = options || {};
    var url = require('url');
    var oauth2 = info.oauth2;
    var directive = info.directive;
    var utils = require('./utils');
    var callbackUrl;
    var parsed;

    // TODO Hmm... make sure this still works when sessions are JWT rather than cookies
    // (it should because the session will be in the express)
    // TODO also, this probably isn't unique enough. probably needs a random state param

    callbackUrl = (
      options.authorizationCodeCallbackUrl ||
      self._authorizationCodeCallbackUrl ||
      self._authorizationCodeCallback // relative url
    );
    parsed = url.parse(callbackUrl);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackUrl = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackUrl);
    }

    //console.log('DEBUG authenticateHelper end');
    return {
      oauth2: oauth2
    , callbackUrl: callbackUrl
    , directive: directive
    };
  });
};

Oauth3Consumer.jwks = function (self, req, options) {
  options = options || {};
  var keyId = req.params.kid;
  var clientUri = req.params.clientUri;

  //console.log('DEBUG o3c jwks', clientUri, keyId);
  return self._keyStore.getAsync(clientUri, keyId).then(function (privkeys) {
    return privkeys;
  });
};
