'use strict';

var PromiseA = require('bluebird').Promise;

module.exports.create = function (conf, deps, app) {
  var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
  var kvStore = deps.memstore;
  var OAuth3 = require('./express-oauth3');
  var DirectiveStore;
  var TokenSigner;

  var options;

  //
  // Example for getting and setting registration information
  // (OAuth3 can automatically register app id / app secret)
  //

  //
  // Automatic Registration
  //
  // For services that support automatic registration, 
  // tell the service your security policy.
  //
  // DRAFT (this is not yet spec'd)
  /*
  function getRegistrationOptions(providerUri) {
    return {
      allowed_domains: [ "https://awesome.com", "https://partner-site.com" ]
    , allowed_cnames: [ "internal.example.com", "external.example.com" ]
    , allowed_redirects: [ "https://awesome.com/oauth3.html", "https://api.awesome.com/oauth3/" ]
    };
  }
  */

  DirectiveStore = {
    getAsync: function (hostnameUri, providerUri) {
      var allConfigs = conf['org.oauth3.consumer'];
      var allDirectives = conf['org.oauth3.provider'];
      var app;
      var creds;
      var directive;
      var result = {};

      if (!allConfigs || !allDirectives) {
        return PromiseA.reject({
          message: "SANITY FAIL: config is missing 'org.oauth3.consumer' and/or 'org.oauth3.provider'"
        , code: "E_SANITY_FAIL"
        });
      }

      app = allConfigs[hostnameUri]; // should be pre-normalized
      directive = allDirectives[providerUri] || {};

      if (app) {
        creds = app[providerUri];
        if (creds) {
          result.config = creds;
          result.directive = directive.directives;
          return PromiseA.resolve(result);
        }
      }

      return PromiseA.reject({
        message: "no config available for '" + hostnameUri + "'"
      , code: "E_NO_CONFIG"
      });
    }
  , setAsync: function (hostnameId, providerUri, config) {
      if (false) {
        console.log(hostnameId, providerUri, config);
        return;
      }

      return PromiseA.reject(new Error("not yet implemented"));
    }
  };

  TokenSigner = {
    // The purpose of this is essentially to establish a session
    signAsync: function (meta, params) {
      /* meta = { referer, host, scope, providerUri, browserState } */
      // https://tools.ietf.org/html/rfc6749#section-4.2.2
      /* params = { access_token, refresh_token, scope, state, token_type, expires_in, expires_at, expires (in) } */

      var request = PromiseA.promisifyAll(require('request'));
      var crypto = require('crypto');
      // "https://facebook.com:765/yoyoy/?#" -> facebook.com/yoyoy
      var re = /(https?:\/\/)?([^:\/]+)(:\d+)?(\/[^#\?]+)?.*/;
      // we probably want to drop the port and any trailing junk after the last '/'
      var appname = (meta.referer || '').replace(re, '$2$4').replace(/\/$/, '');
      var appname2 = (meta.host || '').replace(re, '$2$4').replace(/\/$/, '');
      var issuedAt = Math.floor(Date.now() / 1000);
      var audience = appname;
      var expiresIn = (1 * 60 * 60);
      var expiresAt = Math.floor(new Date(Date.now() + (expiresIn * 1000)).valueOf() / 1000);
      var privkey;
      var issuer;
      var pub;
      var providerUri = meta.providerUri.replace(/\//g, ':');

      function getProfileUrl(resp) {
        var json = (resp.body || resp.data);

        console.log('resp.body', typeof resp.body);
        console.log('resp.data', typeof resp.data);
        if ('string' === typeof json) {
          json = JSON.parse(json);
        }

        if (!(json.profile || json.accounts))) {
          return PromiseA.reject({
            message: "no profile url"
          , code: "E_NO_OAUTH3_ACCOUNTS"
          });
        }

        return (json.profile || json.accounts);
      }

      return request.getAsync('https://' + providerUri + '/oauth3.json').then(getProfileUrl, function (/*err*/) {
        // TODO needs reporting API -> /api/com.oauth3.providers/ + providerUri + /oauth3.json
        var url = 'https://oauth3.org/providers/' + providerUri + '/oauth3.json';

        return request.getAsync(url).then(getProfileUrl, function (/*err*/) {
          var url = 'https://raw.githubusercontent.com/OAuth3/providers/master/' + providerUri + '.json';

          return request.getAsync({
            method: 'GET'
          , url: url
          , headers: {
              'Authorization': 'Bearer ' + params.access_token
            }
          });
        });
      }).then(function (profileUrl) {

        return request.getAsync(profileUrl).then(function (resp) {
          console.log('resp.body', typeof resp.body);
          console.log('resp.data', typeof resp.data);

          var json = (resp.body || resp.data);
          if ('string' === typeof json) {
            json = JSON.parse(json);
          }
          json = json.accounts || json.profile || json;

          if (Array.isArray(json)) {
            return json;
          }

          if (json.appScopedId || json.idx || json.id) {
            return [json];
          }

          // TODO need a way to specify where to grab oauth3.json in request
          return PromiseA.reject({
            message: "'" + meta.providerUri + "' did not provide an id"
          , code: "E_NO_IDS"
          });
        });
      }).then(function (profiles) {

        // TODO need a way to describe app-scoped vs non-app-scoped ids
        // the accounts of one provider become ids for a consumer
        var ids = profiles.map(function (profile) {
          return profile.appScopedId || profile.idx || profile.id || profile;
        }).filter(function (p) { return p; });
        var emails = profiles.reduce(function (arr, profile) {
          if (profile.email) {
            arr.push(profile.email);
          }
          if (Array.isArray(profile.emails)) {
            profile.emails.forEach(function (email) {
              arr.push(email);
            });
          }
          return arr;
        }, []);
        var usernames = profiles.reduce(function (arr, profile) {
          if (profile.username) {
            arr.push(profile.username);
          }
          if (Array.isArray(profile.usernames)) {
            profile.usernames.forEach(function (username) {
              arr.push(username);
            });
          }
          return arr;
        }, []);


        if (conf.keys[appname]) {
          privkey = conf.keys[appname].privkey;
          issuer = appname;
          pub = conf.keys[appname].pubkey;
        } else {
          if (conf.keys[appname2]) {
            privkey = conf.keys[appname2].privkey;
            issuer = appname2;
            pub = conf.keys[appname2].pubkey;
          } else {
            return PromiseA.reject({
              message: "neither '" + appname + "' nor '" + appname2 + "' is configured for signing with a private key"
            , code: "E_NO_PRIVATE_KEY"
            });
          }
        }

        // TODO
        // needs login identifier (grab from facebook, etc?)
        // needs account identifiers array (usually of one)

        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1
        // https://openid.net/specs/draft-jones-json-web-token-07.html (prn became sub)
        // see org.oauth3.provider/oauthclient-microservice/lib/oauth3orize.js
        /* jwt = { jti, iss, aud, sub, typ, iat, exp, data } */
        var accessToken = jwt.sign({
          jti: crypto.randomBytes(16).toString('hex') // prevent replays
        , iat: issuedAt             // IntDate
        , exp: expiresAt            // IntDate

        , iss: issuer               // the audience must trust the public keys of the issuer
        , aud: audience             // the issuer may have multiple audiences and therefore must specify (for the audience's sake)
        , sub: meta.providerUri     // rfc7519 for prn - the subject (principle) - in this case is the 3rd party login
        , typ: 'credentials'        // how to know what

        , data: params              // non-spec, application specific
        , pub: pub                  // non-spec TODO use a fingerprint of the keypair rather than the full public key pem

                                    // hmm... I'd really like to only have one id
        , ids: ids                  // non-spec TODO how can we know the ids are app-scoped?
        , emails: emails
        , usernames: usernames
        //, ixs: ixs                  // non-spec
        }, privkey, { algorithm: 'RS256' });

        // https://tools.ietf.org/html/rfc6749#section-4.2.2
        return {
        // The access token should have a lot of data (prevent db lookups)
          access_token: accessToken
        // The refresh token will require a database lookup (and check if the user is still allowed - PCI/SOX compliance)
        , refresh_token: '' // refreshToken
        // expires_at refers to accessToken, but since it's jwt
        , expires_at: expiresAt
        , expires_in: expiresIn
          // TODO declare what is granted with this token
        , scope: undefined
        , token_type: 'bearer'
        };
      });
    }
  };

  options = {
    // walnut handles '/api/org.oauth3.consumer' as '/'
    // but will also offer it as '/api' and '/api/org.oauth3.consumer'
    // for compatibility
    // TODO allow a way to specify which method is preferred
    oauth3Prefix: '/api/org.oauth3.consumer'
  , oauth3PrefixInternal: '/api/org.oauth3.consumer'
  , authorizationRedirect: '/api/org.oauth3.consumer/authorization_redirect'
  , authorizationCodeCallback: '/api/org.oauth3.consumer/authorization_code_callback'
    // TODO double check that this will template the current host at runtime
  //, authorizationCodeCallbackUrl: /*options.domain +*/ '{{host}}/api/org.oauth3.consumer/authorization_code_callback'
  };

  OAuth3.create(app, TokenSigner, DirectiveStore, kvStore, options);
};
