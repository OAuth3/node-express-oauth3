'use strict';

/**
 * Module dependencies.
 */
var passport = require('passport-strategy');
var util = require('util');
var OAuth2Strategy = require('passport-oauth2');

var PromiseA = require('bluebird').Promise;
var allStates = {};

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
    , expires: Date.now() + (24 * 60 * 60 * 100)
    , provider: providerUri
    };

    return self._directives[providerUri].directive;
  }).error(function (err) {
    return PromiseA.reject(new Error("OAuth3 could not retrieve '" + encodeURI(uri) + "': " + err.message));
  });
}

function fetchDirective(self, providerUri) {
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
  return fetchDirective(self, providerUri).then(function (directive) {
    return self._getOptions(providerUri).then(function (options) {
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

      var oauth2 = new OAuth2(
        appId
      , appSecret
      , baseSite
      , directive.authorization_dialog.url
      , req.query.access_token_uri || req.query.token_uri || directive.access_token.url || options.access_token
      , options.customHeaders || directive.http_headers
      );

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
function OAuth3Strategy(options, verify) {
  var me = this;

  options = options || {};
 
  // OAuth2Strategy.call(me, options, verify);
  if ('function' !== typeof verify) {
    throw new TypeError('OAuth3Strategy requires an options parameter and a verify callback');
  }

  passport.Strategy.call(this);

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

  me._accessTokenCallbackUrl = options.accessTokenCallbackUrl || options.callbackUrl || options.callbackURL;
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
  me._directives = {};
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(OAuth3Strategy, OAuth2Strategy);

function exchangeCodeForToken(self, req, oauth2, fullCallbackUrl, providerUri, options) {
  var code = req.query.code;
  var serverState = req.query.state;
  var metaState;
  var params;

  if (!req.session) {
    self.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
    return;
  }
  
  if (!allStates[serverState]) {
    self.fail({ message: 'Unable to verify authorization request state.' }, 403);
    return;
  }

  metaState = allStates[serverState];
  if ('object' !== typeof metaState) {
    self.fail({ message: 'Unable to verify authorization request state.' }, 403);
    return;
  }
    
  delete allStates[serverState];
  // TODO do this better
  // delete all states that are more than 15 minutes old
  Object.keys(allStates).forEach(function (key) {
    if (Date.now() - allStates[key].createdAt > (15 * 60 * 1000)) {
      delete allStates[key];
    }
  });

  if (metaState.serverState !== req.query.state) {
    self.fail({ message: 'Invalid authorization request state.' }, 403);
    return;
  }

  params = self.tokenParams(options);
  params.grant_type = 'authorization_code';
  params.redirect_uri = fullCallbackUrl;

  oauth2.getOAuthAccessToken(code, params, function(err, accessToken, refreshToken, params) {
    if (err) {
      console.error('OAuth3 Error 1');
      console.warn('Error hint: Double check that App Id and App Secret are correct');
      console.warn('Error hint: Is code is correct?', code);
      console.warn(err);
      self.error(self._createOAuthError('Failed to obtain access token', err));
      return;
    }
    
    self.userProfile(req, providerUri, accessToken, function(err, profile) {
      var promise;

      if (err) {
        console.error('OAuth3 Error 2');
        console.warn(err);
        self.error(err);
        return;
      }
      
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
        console.error('OAuth3 Error 3');
        console.warn(e);
        self.error(e);
        return;
      }

      // TODO return
      promise.then(function (result) {
        if (!result || !result.user) {
          console.error('OAuth3 Error 4');
          console.warn(result);
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
  });
}
function redirectToAuthorizationDialog(self, req, oauth2, providerUri, fullCallbackUrl, scope, options) {
  options = options || {};
  var uid = require('uid2');
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

  if (!req.session) {
    self.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
    return;
  }
  
  serverState = uid(48);
  allStates[serverState] = {
    browserState: browserState
  , serverState: serverState
  , createdAt: Date.now()
  , providerUri: providerUri
  };

  params.state = serverState;
  
  redirectUrl = oauth2.getAuthorizeUrl(params);
  self.redirect(redirectUrl);
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
OAuth3Strategy.prototype.authenticate = function(req, options) {
  if (!req.query) {
    req.query = {};
  }

  var self = this;
  var providerUri = req.query.provider_uri;
  // Note: this could also be browser state, but for the purposes here, it would need to be the server state
  var serverState = req.query.state;
  var err;

  if (!providerUri) {
    if (req.params && req.params.providerUri) {
      providerUri = decodeURIComponent(req.params.providerUri);
    }
    else if (allStates[serverState] && allStates[serverState].providerUri) {
      providerUri = allStates[serverState].providerUri;
    } else {
      err = new Error("provider_uri must be passed as a url param, a query param, or related to the state param");
      err.code = "E_NO_PROVIDER_URI";
      return PromiseA.reject(err);
    }
  }

  if (!/^(https?|spdy):\/\//.test(providerUri)) {
    providerUri = 'https://' + providerUri;
  }

  return getOauthClient(self, req, providerUri).then(function (info) {
    options = options || {};
    var url = require('url');
    var oauth2 = info.oauth2;
    var directive = info.directive;
    var AuthorizationError = require('passport-oauth2/lib/errors/authorizationerror');
    var utils = require('passport-oauth2/lib/utils');
    var callbackUrl;
    var parsed;
    var scope;
    
    if (req.query.error) {
      if (req.query.error === 'access_denied') {
        self.fail({ message: req.query.error_description });
        return;
      } else {
        self.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        return;
      }
    }
    
    // TODO Hmm... make sure this still works when sessions are JWT rather than cookies
    // (it should because the session will be in the express)
    // TODO also, this probably isn't unique enough. probably needs a random state param
    
    if (!req.query.code) {
      // TODO access_token_uri must be documented
      // This is done in getOauthClient above, but maybe should be done here
      // oauth2._accessTokenUrl = req.query.access_token_uri || req.query.token_uri || oauth2._accessTokenUrl;
      callbackUrl = options.accessTokenCallbackUrl || self._accessTokenCallbackUrl;
      parsed = url.parse(callbackUrl);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackUrl = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackUrl);
      }
      scope = req.query.scope || options.scope || self._scope || directive.authn_scope;
      redirectToAuthorizationDialog(self, req, oauth2, providerUri, callbackUrl, scope, options);
    } else {
      callbackUrl = options.authorizationCodeCallbackUrl || self._authorizationCodeCallbackUrl;
      parsed = url.parse(callbackUrl);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackUrl = url.resolve(utils.originalURL(req, { proxy: self._trustProxy }), callbackUrl);
      }
      exchangeCodeForToken(self, req, oauth2, callbackUrl, providerUri, options);
    }
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
OAuth3Strategy.prototype.userProfile = function (req, providerUri, accessToken, done) {
  var me = this;

  return getOauthClient(me, req, providerUri).then(function (info) {
  //return fetchDirective(me, providerUri).then(function (directive)
    var directive = info.directive;
    var oauth2 = info.oauth2;

    function conditionalParse(body, done) {
      var json;

      if ('string' === typeof body) {
        try {
          json = JSON.parse(body);
        }
        catch(e) {
          var err = new Error('[OAuth3Strategy] Error parsing json');
          err.body = body;
          done(err);
          return;
        }
      } else if ('object' === typeof body) {
        json = body;
      }

      done(null, json);
    }

    oauth2.get(
      directive.profile.url
    , accessToken
    , function (err, body/*, res*/) {
        var InternalOAuthError = require('passport-oauth2/lib/errors/internaloautherror');
        if (err) { return done(new InternalOAuthError('failed to fetch user account list', err)); }

        conditionalParse(body, done);
      }
    );
  });
};

/**
 * Expose `Strategy`.
 */
module.exports.Strategy = OAuth3Strategy.Strategy = OAuth3Strategy.OAuth3Strategy = OAuth3Strategy;
