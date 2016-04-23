'use strict';

var Oauth3 = module.exports = {
  Consumer: require('./lib/consumer')
, Routes: require('./lib/routes')
, Router: require('./lib/router')
, create: function (app, TokenSigner, ConfigStore, KeyStore, KeyValueStore, options) {
    options = options || {};

    options.oauth3Prefix = options.oauth3Prefix || '/api/org.oauth3.consumer';
    options.oauth3PrefixInternal = options.oauth3PrefixInternal || '/api/org.oauth3.consumer';
    options.authorizationRedirect = options.authorizationRedirect || '/api/org.oauth3.consumer/authorization_redirect';
    options.authorizationCodeCallback = options.authorizationCodeCallback || '/api/org.oauth3.consumer/authorization_code_callback';
    options.jwks = options.jwks || '/api/org.oauth3.consumer/jwks';

    if (options.domain && !options.authorizationCodeCallbackUrl) {
      options.authorizationCodeCallbackUrl = options.domain + options.authorizationCodeCallback;
    }

    var consumer = options.consumer || Oauth3.Consumer.create(TokenSigner, ConfigStore, KeyStore, KeyValueStore, options);
    var routes = options.routes || Oauth3.Routes.create(Oauth3.Consumer, consumer, options);

    if ('string' !== typeof options.authorizationRedirect || !/^\/\w/.test(options.authorizationRedirect)) {
      throw new Error(
        'options.authorizationRedirect should be a string'
      + ' in the format /api/oauth3/authorization_redirect'
      + ' Note that /:providerUri will be appended as an optional variable and'
      + ' the ?provider_uri=example.com query search parameter will also be honored'
      );
    }

    return Oauth3.Router.create(app, routes, options);
  }
};
