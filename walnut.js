'use strict';

var PromiseA = require('bluebird').Promise;

module.exports.create = function (conf, deps, app) {
  var kvStore = deps.memstore;
  var OAuth3 = require('./express-oauth3');
  var DirectiveStore;

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

  OAuth3.create(app, DirectiveStore, kvStore, options);
};
