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
    signAsync: function (data) {
      // "https://facebook.com:765/yoyoy/?#"
      var abnormalHostname = (data.referer || '');
      var abnormalHostname2 = (data.host || '');
      var appname = abnormalHostname.replace(/(https?:\/\/)?([^:\/]+)(:\d+)?(\/[^#\?]+)?.*/, '$2$4').replace(/\/$/, '');
      var appname2 = abnormalHostname2.replace(/(https?:\/\/)?([^:\/]+)(:\d+)?(\/[^#\?]+)?.*/, '$2$4').replace(/\/$/, '');
      var issuedAt = Math.floor(Date.now() / 1000);
      var privkey;
      // we probably want to drop the port and any trailing junk after the last '/'

      if (conf.keys[appname]) {
        privkey = conf.keys[appname].privkey;
      } else {
        if (conf.keys[appname2]) {
          privkey = conf.keys[appname2].privkey;
        } else {
          return PromiseA.reject({
            message: "'" + appname + "' is not configured for signing with a private key"
          , code: "E_NO_PRIVATE_KEY"
          });
        }
      }

      // NOTE data.scope is available for reference
      // TODO perform login and attack acs to this session token
      // see org.oauth3.provider/oauthclient-microservice/lib/oauth3orize.js
      var tok = jwt.sign({
        accessToken: data.params.access_token
      , consumer: appname // aud?
      , refreshToken: data.params.refresh_token
      , providerUri: data.providerUri
      , params: data.params // expirey?
      , iat: issuedAt
      //, exp: ''
      }, privkey, { algorithm: 'RS256' });

      return PromiseA.resolve(tok);
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
