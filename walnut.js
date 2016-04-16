'use strict';

module.exports.create = function (xconfx, deps, app) {
  var kvStore = deps.memstore;
  var OAuth3 = require('./express-oauth3');
  // DirectiveStore is directive + registration
  // TODO add keys
  var things = require('./lib/stores-abstract').create(xconfx, require('./lib/request-oauth3').getAsync);
  var DirectiveStore = require('./lib/directive-store').create(things.DirStore, things.RegStore);
  var TokenSigner = require('./lib/token-signer').create(things.DirStore, things.KeyStore);

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


  // TODO clean-up, 'things' should be passed in

  return OAuth3.create(xconfx, app, TokenSigner, DirectiveStore, kvStore, options);
};
