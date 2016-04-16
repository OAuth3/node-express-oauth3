'use strict';

module.exports.create = function (xconfx, deps, app) {
  var kvStore = deps.memstore;
  var OAuth3 = require('./express-oauth3');
  // DirectiveStore is directive + registration
  // TODO add keys
  var things = require('./lib/stores-abstract').create(xconfx, require('./lib/request-oauth3').getAsync);
  var DirectiveStore = require('./lib/directive-store').create(things.DirStore, things.RegStore);
  var TokenSigner = require('./lib/token-signer').create(things.DirStore, things.KeyStore);

  var options = {
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

  // TODO clean-up, maybe 'things' should be passed in ?

  return OAuth3.create(xconfx, app, TokenSigner, DirectiveStore, kvStore, options);
};
