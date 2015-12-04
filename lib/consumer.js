'use strict';

var Oauth3Consumer = module.exports = function () {};

/**
 * Module dependencies.
 */
var PromiseA = require('bluebird').Promise;
var crypto = require('crypto');

function lintUrl(name, uri) {
  var url;
  var parsed;

  if (!uri) {
    throw (new Error("OAuth3 requires '" + encodeURIComponent(name) + "'."
      + " Ex: '&" + encodeURIComponent(name) + "=' + encodeURIComponent('https://example.com')"));
  }

  url = require('url');
  parsed = url.parse(uri);

  if ('http:' === parsed.protocol) {
    throw (new Error("OAuth3 requires an encrypted connection, but you provided a non-encrypted url."
      + " See https://letsencrypt.org for a free SSL certificate."));
  }

  if (('https:' !== parsed.protocol && 'spdy:' !== parsed.protocol) || !parsed.slashes) {
    throw (new Error("OAuth3 requires a full URI for '" + encodeURIComponent(name)
      + "', including the leading protocol https://"));
  }

  if (parsed.auth) {
    throw (new Error("OAuth3 requires that you do not supply a password when using Basic Authentication"
      + " (https://user:pass@example.com should be https://user@example.com) for '"
      + encodeURIComponent(name) + "'"
    ));
  }

  /*
  if ('/' !== uri[uri.length - 1]) {
    uri += '/';
  }
  */

  return uri;
}

// TODO this belongs elsewhere
function pruneDirectives(directives, len) {
  // prevent the directive list from growing infinitely long
  // (i.e. an attack)
  var leftovers = Object.keys(directives).filter(function (key) {
    // only remove dynamically discovered providers
    if (!directives[key].dynamic) {
      return;
    }
  }).sort(function (a, b) {
    // sort from least recently updated to most recently updated
    // i.e. [yesterday, today, 5 minutes ago, just now]
    return directives[b].updated - directives[a].updated;
  }).slice(len);
  directives.length = leftovers.length;
  leftovers.forEach(function (key) {
    // delete all of the old ones
    delete directives[key];
  });
}

function realFetchDirective(self, providerUri) {
  // use an oauth3 / oauth2 mapping service as a fallback
  var requestAsync;
  var uri;

  try {
    uri = lintUrl('provider_uri', providerUri);
  } catch(e) {
    return PromiseA.reject(e);
  }

  if ('/' !== providerUri[providerUri.length - 1]) {
    providerUri += '/';
  }

  requestAsync = PromiseA.promisify(require('request'));
  uri = providerUri + 'oauth3.json';

  // TODO limit size to prevent attack
  return requestAsync({ url: uri }).spread(function (resp, body) {
    var json;

    try {
      json = JSON.parse(body);
    } catch(e) {
      // ignore
      return PromiseA.reject(new Error("Oauth3 could not parse '" + encodeURI(uri) + "' as valid json"));
    }

    // TODO lint urls and everything
    try {
      lintUrl('authorization_dialog', json.authorization_dialog.url);
    } catch(e) {
      e.message = "Bad oauth.json: authorization_dialog " + e.message;
      return PromiseA.reject(e);
    }
    try {
      lintUrl('access_token', json.access_token.url);
    } catch(e) {
      e.message = "Bad oauth.json: access_token " + e.message;
      return PromiseA.reject(e);
    }

    if ('string' !== typeof json.authn_scope) {
      return PromiseA.reject(new Error("Bad oauth.json: "
        + "authn_scope should be a string (even if it's an empty one)"));
    }
    try {
      lintUrl('profile', json.profile.url);
    } catch(e) {
      return PromiseA.reject(e);
    }
    /*
    try {
      lintUrl('accounts', json.authorization_dialog);
    } catch(e) {
      return PromiseA.reject(e);
    }
    */

    // TODO respect expires header
    if (!self._directives[providerUri]) {
      self._directives.length += 1;
      // todo make length an option
      if (self._directives.length >= 1000) {
        pruneDirectives(self._directives, 100);
      }
    }

    self._directives[providerUri] = {
      dynamic: true
    , updated: Date.now()
    , directive: json
    , expires: Date.now() + (24 * 60 * 60 * 1000)
    , provider: providerUri
    };

    return self._directives[providerUri].directive;
  }).error(function (err) {
    return PromiseA.reject(new Error("Oauth3 could not retrieve '" + encodeURI(uri) + "': " + err.message));
  });
}

Oauth3Consumer.stripLeadingProtocolAndTrailingSlash = function (uri) {
  return uri.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
};

Oauth3Consumer.directive = function (self, providerUri, providerDirectives) {
  // TODO user-configured object with fetch callback
  if (providerDirectives) {
    return PromiseA.resolve(providerDirectives);
  }

  var directive = self._directives[providerUri] || {};
  var now = Date.now();
  var fresh;

  // TODO implement
  /*
  if (directive.tried >= 3 && directive.retryAfter - now > 0) {
    return PromiseA.reject(new Error("This server doesn't reply to oauth3.json and is in"
      + " cooldown for " + (directive.retryAfter - now / 1000).toFixed(0) + "s"));
  }
  */

  if (!directive.directive) {
    return realFetchDirective(self, providerUri);
  }

  fresh = directive.expires - now > 0;
  if (!fresh) {
    realFetchDirective(self, providerUri);
  }

  return PromiseA.resolve(directive.directive);
};

Oauth3Consumer._getOauthClient = function (self, req, providerUri) {
  var normalHostname = Oauth3Consumer.stripLeadingProtocolAndTrailingSlash(req.hostname);
  var normalProviderUri = Oauth3Consumer.stripLeadingProtocolAndTrailingSlash(providerUri);

  return self._ds.getAsync(normalHostname, normalProviderUri).then(function (result) {
    var conf = result.config;
    var directive = result.directive || result.directives;

    return Oauth3Consumer.directive(self, providerUri, directive).then(function (directive) {
      // TODO automatic registration via directive.registration if conf.appId is missing

      var OAuth2 = require('oauth').OAuth2;
      var baseSite = ''; // leave as empty string so that Oauth3 (requires absolute URLs) can create its own
      var appId = conf.id
          || conf.appId || conf.appID
          || conf.consumerId || conf.consumerID
          || conf.clientId || conf.clientID
          ;
      var appSecret = conf.secret || conf.clientSecret || conf.consumerSecret || conf.appSecret;

      if (!conf || !appSecret) {
        return PromiseA.reject({
          message: "Automatic Registration not implemented yet. Cannot OAuth-orize '" + providerUri + "'"
        , code: "E_NOT_REGISTERED"
        });
      }

      // TODO create instanceless Oauth3 module
      var oauth2 = PromiseA.promisifyAll(new OAuth2(
        appId
      , appSecret
      , baseSite
      , directive.authorization_dialog.url
      , req.query.access_token_uri || req.query.token_uri || directive.access_token.url || conf.access_token
      , directive.http_headers
      ), { multiArgs: true });

      return { oauth2: oauth2, directive: directive };
    });
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

Oauth3Consumer.create = function (Signer, DirectiveStore, kvStore, options) {
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

  if ('function' !== typeof DirectiveStore.getAsync) {
    throw new Error("Implement 'DS.getAsync' as 'function (hostnameId, providerUri) { return Promise.resolve({ id: 'id', secret: 'secret' }); }");
  }
  if (2 !== DirectiveStore.getAsync.length) {
    throw new Error("'DS.getAsync' should accept exactly 2 parameters: tenantUri, providerUri");
  }
  if ('function' !== typeof DirectiveStore.setAsync) {
    throw new Error("Implement 'DS.setAsync' as 'function (hostnameId, providerUri, conf) { return Promise.resolve(); }");
  }
  if (3 !== DirectiveStore.setAsync.length) {
    throw new Error("'DS.setAsync' should accept exactly 3 parameters: hostnameId, providerUri, config");
  }

  var me = {};
  me.options = options;

  me._authorizationCodeCallback = options.authorizationCodeCallback;
  me._scopeSeparator = options.scopeSeparator || ' ';
  // in Oauth3 this is non-optional
  me._trustProxy = options.proxy;

  me._ds = DirectiveStore;

  me._kv = kvStore;
  me._signer = Signer;
  if (!me._kv.getAsync) {
    me._kv = PromiseA.promisifyAll(kvStore, { multiArgs: false });
  }

  // XXX TODO XXX this need use the KV store
  me._directives = {};

  return me;
};

function exchangeCodeForToken(self, req, oauth2, fullCallbackUrl, metaState/*, options*/) {
  var code = req.query.code;

  // TODO pull from directive
  var requestQuery = {};

  requestQuery.grant_type = 'authorization_code';
  requestQuery.redirect_uri = fullCallbackUrl;

  return oauth2.getOAuthAccessTokenAsync(code, requestQuery).spread(function (accessToken, refreshToken, params) {
    var expiresAt;
    var result;

    if (parseInt(params.expires, 10)) {
      expiresAt = new Date(Date.now() + (parseInt(params.expires, 10) * 1000));
    }

    result = {
      referer: metaState.referer
    , host: metaState.host
    , scope: metaState.scope
    , providerUri: metaState.providerUri
    , params: params
    };

    result.params.access_token = accessToken;
    result.params.refresh_token = refreshToken;

    return self._signer.signAsync(result).then(function (tok) {
      result.params.browser_state = metaState.browserState;
      result.params.oauth3_token = tok;
      result.params.expires_at = expiresAt;

      // xxx TODO xxx TODO xxx jwt
      return result;
    });
  });
}

function redirectToAuthorizationDialog(self, req, oauth2, providerUri, fullCallbackUrl, scope/*, directive*/) {
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
  metaState = {
    browserState: browserState
  , serverState: serverState
  , referer: req.headers.referer
  , host: req.headers.host
  , scope: params.scope
  , createdAt: Date.now()
  , providerUri: providerUri
  };

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
  options = options || {};
  var self = strategy;
  var providerUri = req.query.provider_uri || (req.params.providerUri && decodeURIComponent(req.params.providerUri));

  return Oauth3Consumer.authenticateHelper(strategy, req, providerUri, options).then(function (helpers) {
    var scope = req.query.scope || options.scope || helpers.directive.authn_scope;
    return redirectToAuthorizationDialog(self, req, helpers.oauth2, providerUri, helpers.callbackUrl, scope, helpers.directive);
  });
};

Oauth3Consumer.authorizationCodeCallback = function (conf, req, options) {
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
      // TODO err.code = 'E_INVALID_STATE';
      return PromiseA.reject(err);
    }

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
    });
  });
};

Oauth3Consumer.authenticateHelper = function (self, req, providerUri, options) {
  var err;

  if (!providerUri) {
    err = new Error("provider_uri must be passed as a url param, a query param, or related to the state param");
    err.code = "E_NO_PROVIDER_URI";
    return PromiseA.reject(err);
  }

  if (!/^(https?|spdy):\/\//.test(providerUri)) {
    providerUri = 'https://' + providerUri;
  }

  return Oauth3Consumer._getOauthClient(self, req, providerUri).then(function (info) {
    options = options || {};
    var err;
    var url = require('url');
    var oauth2 = info.oauth2;
    var directive = info.directive;
    var AuthorizationError = require('./errors/authorizationerror');
    var utils = require('./utils');
    var callbackUrl;
    var parsed;
    
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

    return {
      oauth2: oauth2
    , callbackUrl: callbackUrl
    , directive: directive
    };
  });
};
