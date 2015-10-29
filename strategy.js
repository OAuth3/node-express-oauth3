'use strict';

/**
 * Module dependencies.
 */
var crypto = require('crypto');
var util = require('util');
var OAuth2Strategy = require('./passport-oauth2');
var querystring = require('querystring');

var PromiseA = require('bluebird').Promise;

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
      return PromiseA.reject(new Error("OAuth3 could not parse '" + encodeURI(uri) + "' as valid json"));
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
    return PromiseA.reject(new Error("OAuth3 could not retrieve '" + encodeURI(uri) + "': " + err.message));
  });
}

function fetchDirective(self, providerUri, options) {
  // TODO user-configured object with fetch callback
  if (options && options.directives) {
    return PromiseA.resolve(options.directives);
    /*
    return PromiseA.resolve({
      dynamic: false
    , updated: Date.now()
    , directive: options.directives
    , expires: Date.now() + (365 * 24 * 60 * 60 * 1000) // never
    , provider: providerUri
    });
    */
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
}

function getOauthClient(self, req, providerUri) {
  return self._getOptions(providerUri).then(function (options) {
    return fetchDirective(self, providerUri, options).then(function (directive) {
      // TODO automatic registration via directive.registration if options.appId is missing
      var OAuth2 = require('oauth').OAuth2;
      var baseSite = ''; // OAuth3 requires absolute URLs
      var appId = options.id
          || options.appId || options.appID
          || options.consumerId || options.consumerID
          || options.clientId || options.clientID
          ;
      var appSecret = options.secret || options.clientSecret || options.consumerSecret || options.appSecret;

      if (!options || !appSecret) {
        return PromiseA.reject("Automatic Registration not implemented yet. Cannot OAuth-orize '" + providerUri + "'");
      }

      var oauth2 = PromiseA.promisifyAll(new OAuth2(
        appId
      , appSecret
      , baseSite
      , directive.authorization_dialog.url
      , req.query.access_token_uri || req.query.token_uri || directive.access_token.url || options.access_token
      , options.customHeaders || directive.http_headers
      ));

      return { oauth2: oauth2, directive: directive };
    });
  });
}

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
 * @param {Function} verify
 * @api public
 */
function OAuth3Strategy(options, kvStore, verify) {
  var me = this;

  options = options || {};
 
  // OAuth2Strategy.call(me, options, verify);
  if ('function' !== typeof verify) {
    throw new TypeError('OAuth3Strategy requires an options parameter and a verify callback');
  }

  me.name = 'oauth3';
  me._verify = verify;
  // NO Jiggery Pokery!!! Just give the params!!!
  //this._passReqToCallback = true;
  // NO private implementation details!!!
  //me._skipUserProfile = true;

  // must be called after prototype is modified

  /*
  if (!options.authorizationURL) { throw new TypeError('OAuth2Strategy requires a authorizationURL option'); }
  if (!options.tokenURL) { throw new TypeError('OAuth2Strategy requires a tokenURL option'); }
  if (!options.clientID) { throw new TypeError('OAuth2Strategy requires a clientID option'); }
  if (!options.clientSecret) { throw new TypeError('OAuth2Strategy requires a clientSecret option'); }

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  me._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
      '', options.authorizationURL, options.tokenURL, options.customHeaders);
  */

  //me._accessTokenCallbackUrl = options.accessTokenCallbackUrl || options.callbackUrl || options.callbackURL;
  me._authorizationCodeCallbackUrl = options.authorizationCodeCallbackUrl || options.callbackUrl || options.callbackURL;
  me._scope = options.scope;
  me._scopeSeparator = options.scopeSeparator || ' ';
  // in OAuth3 this is non-optional
  me._state = true; //(false === options.state ? false : true);
  me._trustProxy = options.proxy;
  if ('function' !== typeof options.providerCallback) {
    throw new Error("Implement 'options.providerCallback' as 'function (providerUri) { return Promise.resolve({ id: 'id', secret: 'secret' }); }");
  }
  if (1 !== options.providerCallback.length) {
    throw new Error("'options.providerCallback' should only accept 1 parameter: providerUri");
  }
  if ('function' !== typeof options.registrationCallback) {
    throw new Error("Implement 'options.registrationCallback' as 'function (providerUri, conf) { return Promise.resolve(); }");
  }
  if (2 !== options.registrationCallback.length) {
    throw new Error("'options.providerCallback' should accept exactly 2 parameters: providerUri, config");
  }
  me._getOptions = options.providerCallback;
  me._setOptions = options.registrationCallback;
  me._frontend = options.frontend;

  me._kv = kvStore;
  if (!me._kv.getAsync) {
    me._kv = PromiseA.promisifyAll(kvStore);
  }
  // XXX TODO XXX this need use the KV store
  me._directives = {};
}
OAuth3Strategy.create = function (app, options, kvStore, getUserFromToken) {
  console.log('[options]', options);
  /*
  if ('string' !== typeof options.accessTokenCallback || !/^\/\w/.test(options.accessTokenCallback)) {
    throw new Error(
      'options.accessTokenCallback should be a string'
    + ' in the format /api/oauth3/access_token_callback'
    + ' Note that /:providerUri will be appended as an optional variable and'
    + ' the ?provider_uri=example.com query search parameter will also be honored'
    );
  }
  */
  if ('string' !== typeof options.authorizationRedirect || !/^\/\w/.test(options.authorizationRedirect)) {
    throw new Error(
      'options.authorizationRedirect should be a string'
    + ' in the format /api/oauth3/authorization_redirect'
    + ' Note that /:providerUri will be appended as an optional variable and'
    + ' the ?provider_uri=example.com query search parameter will also be honored'
    );
  }
  if ('string' !== typeof options.authorizationCodeCallback || !/^\/\w/.test(options.authorizationCodeCallback)) {
    throw new Error(
      'options.authorizationCodeCallback should be a string'
    + ' in the format /api/oauth3/authorization_code_callback'
    + ' Note that /:providerUri will be appended as an optional variable and'
    + ' the ?provider_uri=example.com query search parameter will also be honored'
    );
  }
  if ('string' !== typeof options.domain || !/^https:\/\//.test(options.domain)) {
    throw new Error(
      'options.domain should be a string'
    + ' in the format https://example.com'
    );
  }
  // TODO make dynamic by hostname
  //options.accessTokenCallbackUrl = options.domain + options.accessTokenCallback;
  options.authorizationCodeCallbackUrl = options.domain + options.authorizationCodeCallback;

  var strategy = new OAuth3Strategy(options, kvStore, getUserFromToken);
  /*
      .then(function (profile) {
        var promise;
        
        try {
          promise = self._verify(
            req
          , providerUri
          , { accessToken: accessToken
            , refreshToken: refreshToken
            , profile: profile
            , appScopedId: params.app_scoped_id
              // TODO options._scopeSeparator
            , grantedScopes: (params.granted_scopes||'').split(/[,\s]/g)
            , browserState: metaState.browserState
            , state: metaState.browserState
            }
          , params
          );
        } catch(e) {
          console.error('[OAuth3 Error 3] getUserFromToken callback failed');
          console.warn(e.message);
          console.warn(e.stack);

          throw e;
        }

        // TODO return
        promise.then(function (result) {
          var err;

          if (!result || !result.user) {
            err = new Error('no user could be fetched');
            console.error('[OAuth3 Error 4']);
            console.warn(result);

            return PromiseA.reject();
            self.fail(result && result.info || { error: { message: "no user could be fetched" } });
            return;
          }

          self.success(result.user, result.info);
        }).catch(function (e) {
          console.error('OAuth3 Error 5');
          console.warn(e);
          self.error(e);
        });
      });
  */

  // TODO options should not anylonger be necessary
  // options = { scope, /*accessTokenCallbackUrl,*/ authorizationCodeCallbackUrl, _scopeSeparator }
  //app.get(options.authorizationRedirect, strategy.authenticate);
  app.get(options.authorizationRedirect, strategy.authorizationRedirect(/*options*/));
  app.get(options.authorizationRedirect + '/:providerUri', strategy.authorizationRedirect(/*options*/));
  app.get(options.authorizationCodeCallback, strategy.authorizationCodeCallback(/*options*/));
  app.get(options.authorizationCodeCallback + '/:providerUri', strategy.authorizationCodeCallback(/*options*/));
  //app.post(options.accessTokenCallback, strategy.authorizationCodeCallback(/*options*/));
  //app.post(options.accessTokenCallback + '/:providerUri', strategy.authorizationCodeCallback(/*options*/));
};

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(OAuth3Strategy, OAuth2Strategy);

function exchangeCodeForToken(self, req, oauth2, fullCallbackUrl, providerUri, options) {
  var code = req.query.code;
  var serverState = req.query.state;
  var params;

  return self._kv.getAsync(serverState).then(function (metaState) {
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
      
    self._kv.deleteAsync(serverState);
    /*
    // TODO do this better
    // delete all states that are more than 15 minutes old
    Object.keys(allStates).forEach(function (key) {
      if (Date.now() - allStates[key].createdAt > (15 * 60 * 1000)) {
        delete allStates[key];
      }
    });
    */

    if (metaState.serverState !== req.query.state) {
      err = new Error('Invalid authorization request state.');
      err.status = 403;
      // TODO err.code = 'E_INVALID_STATE';
      return PromiseA.reject(err);
    }

    params = self.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.redirect_uri = fullCallbackUrl;

    return oauth2.getOAuthAccessTokenAsync(code, params).spread(function (accessToken, refreshToken, params) {
      return {
        accessToken: accessToken
      , refreshToken: refreshToken
      , params: params
      };
    }, function (err) {
      console.error('OAuth3 Error 1');
      console.warn('Error hint: Double check that App Id and App Secret are correct');
      console.warn('Error hint: Is code is correct?', code);
      console.warn(err.message);
      console.warn(err.stack);

      return PromiseA.reject(self._createOAuthError('Failed to obtain access token', err));
    });
  });
}

function redirectToAuthorizationDialog(self, req, oauth2, providerUri, fullCallbackUrl, scope, options) {
  options = options || {};
  var params;
  var browserState;
  var serverState;
  var redirectUrl;

  params = self.authorizationParams(options);
  params.response_type = 'code';
  params.redirect_uri = fullCallbackUrl;
  if (scope) {
    if (Array.isArray(scope)) { scope = scope.join(self._scopeSeparator); }
    params.scope = scope;
  }
  browserState = params.state || req.query.browser_state || req.query.state;

  /*
  if (!req.session) {
    err = new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?');
    // TODO err.code = 'E_NO_SESSION';
    return PromiseA.reject(err);
  }
  */
  
  serverState = crypto.randomBytes(32).toString('hex');

  return self._kv.setAsync(serverState, {
    browserState: browserState
  , serverState: serverState
  , createdAt: Date.now()
  , providerUri: providerUri
  }).then(function () {
    params.state = serverState;
    // TODO inject redirect_uri here
    redirectUrl = oauth2.getAuthorizeUrl(params);
    return redirectUrl;
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
OAuth3Strategy.prototype.authorizationRedirect = function (options) {
  var self = this;

  return function (req, res) {
    return self.authenticate(req, options).then(function (redirectUrl) {
      res.redirect(redirectUrl);
    }, function (err) {
      console.error('[Authenticate Error]');
      console.error(err.message);
      console.error(err.stack);
      // TODO reirect with error uri?
      res.send({
        error: err.code || err.message
      , error_description: err.message
      , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_0')
      });
    }).catch(function (err) {
      console.error('[UNKNOWN OAUTH3 EXCEPTION]');
      console.error(err.message);
      console.error(err.stack);
      res.send({
        error: 'E_UNEXPECTED_ERROR'
      , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
      , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_1')
      });
    });
  };
};

OAuth3Strategy.prototype.authorizationCodeCallback = function (options) {
  var self = this;

  return function (req, res) {
    return self.authenticate(req, options).then(function (result) {
      console.log(result);

      res.redirect('/oauth3.html#' + querystring.stringify(result.params));

      // return self.userProfileAsync(req, providerUri, accessToken).then(function () {});
    }, function (err) {
      // TODO reirect with error uri?
      res.send({
        error: err.code || err.message
      , error_description: err.message
      , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_2')
      });
    }).catch(function (err) {
      console.error('[UNKNOWN OAUTH3 EXCEPTION]');
      console.error(err.message);
      console.error(err.stack);
      res.send({
        error: 'E_UNEXPECTED_ERROR'
      , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
      , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_3')
      });
    });
  };
};

OAuth3Strategy.prototype.authenticate = function (req, options) {
  // TODO express should handle these
  if (!req.query) {
    req.query = {};
  }
  if (!req.params) {
    req.params = {};
  }

  console.log('[req.query]', req.query);
  console.log('[req.params]', req.params);

  var self = this;
  var providerUri = req.query.provider_uri || (req.params.providerUri && decodeURIComponent(req.params.providerUri));
  // Note: this could also be browser state, but for the purposes here, it would need to be the server state
  var serverState = req.query.state;
  var promise;

  if (providerUri) {
    promise = PromiseA.resolve(providerUri);
  }
  else {
    promise = self._kv.getAsync(serverState).then(function (metaState) {
      var err;

      if (metaState && metaState.providerUri) {
        return metaState.providerUri;
      }     

      err = new Error("provider_uri must be passed as a url param, a query param, or related to the state param");
      err.code = "E_NO_PROVIDER_URI";
      return PromiseA.reject(err);
    });
  }

  return promise.then(function (providerUri) {
    if (!/^(https?|spdy):\/\//.test(providerUri)) {
      providerUri = 'https://' + providerUri;
    }

    return getOauthClient(self, req, providerUri).then(function (info) {
      options = options || {};
      var err;
      var url = require('url');
      var oauth2 = info.oauth2;
      var directive = info.directive;
      var AuthorizationError = require('./errors/authorizationerror');
      var utils = require('./utils');
      var callbackUrl;
      var parsed;
      var scope;
      
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
      
      if (!req.query.code) {
        // TODO access_token_uri must be documented
        // This is done in getOauthClient above, but maybe should be done here
        // oauth2._accessTokenUrl = req.query.access_token_uri || req.query.token_uri || oauth2._accessTokenUrl;
        //callbackUrl = options.accessTokenCallbackUrl || self._accessTokenCallbackUrl;
        callbackUrl = options.authorizationCodeCallbackUrl || self._authorizationCodeCallbackUrl;
        parsed = url.parse(callbackUrl);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackUrl = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackUrl);
        }
        scope = req.query.scope || options.scope || self._scope || directive.authn_scope;
        return redirectToAuthorizationDialog(self, req, oauth2, providerUri, callbackUrl, scope, options);
      } else {
        callbackUrl = options.authorizationCodeCallbackUrl || self._authorizationCodeCallbackUrl;
        parsed = url.parse(callbackUrl);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackUrl = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackUrl);
        }
        return exchangeCodeForToken(self, req, oauth2, callbackUrl, providerUri, options);
      }
    });
  });
};

/**
 * Retrieve user profile from example-oauth2orize.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `example-oauth2orize`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
OAuth3Strategy.prototype.userProfileAsync = function (req, providerUri, accessToken) {
  var me = this;

  return getOauthClient(me, req, providerUri).then(function (info) {
    var directive = info.directive;
    var oauth2 = info.oauth2;

    function conditionalParse(body) {
      var json;

      if ('string' === typeof body) {
        try {
          json = JSON.parse(body);
        }
        catch(e) {
          var err = new Error('[OAuth3Strategy] Error parsing json');
          err.body = body;
          return PromiseA.reject(err);
        }
      } else if ('object' === typeof body) {
        json = body;
      }

      return json;
    }

    oauth2.getAsync(
      directive.profile.url
    , accessToken
    ).spread(function (err, body/*, res*/) {
      return conditionalParse(body);
    }, function (err) {
        var InternalOAuthError = require('./errors/internaloautherror');
        return PromiseA.reject(new InternalOAuthError('failed to fetch user account list', err));
    });
  });
};





/******************************************
      OVERRIDES
 ******************************************/

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.tokenParams = function(/*options*/) {
  return {};
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
OAuth2Strategy.prototype.authorizationParams = function(/*options*/) {
  return {};
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
OAuth2Strategy.prototype.parseErrorResponse = function(body/*, status*/) {
  var TokenError = require('./errors/tokenerror');
  var json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
OAuth2Strategy.prototype._createOAuthError = function(message, err) {
  var InternalOAuthError = require('./errors/internaloautherror');
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {
      console.error('[OAuth2 Error]');
      console.error(_.message);
      console.error(_.stack);
    }
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};





/**
 * Expose `Strategy`.
 */
module.exports.Strategy = OAuth3Strategy.Strategy = OAuth3Strategy.OAuth3Strategy = OAuth3Strategy;
