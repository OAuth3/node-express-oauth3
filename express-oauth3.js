'use strict';

var Oauth3 = module.exports = {
  Consumer: require('./consumer')
, Routes: require('./routes')
, Router: require('./router')
};

module.exports.Consumer.standalone = function (app, DirectiveStore, KeyValueStore, options) {
  options = options || {};

  options.oauth3Prefix = options.oauth3Prefix || '/api/oauth3';
  options.authorizationRedirect = options.authorizationRedirect || '/api/oauth3/authorization_redirect';
  options.authorizationCodeCallback = options.authorizationCodeCallback || '/api/oauth3/authorization_redirect';
  // TODO make dynamic by incoming hostname ?
  options.authorizationCodeCallbackUrl = options.domain + options.authorizationCodeCallback;

  var consumer = new Oauth3.Consumer(DirectiveStore, KeyValueStore, options);
  var routes = require('./routes').create(Oauth3.Consumer, consumer, options);

  if ('string' !== typeof options.authorizationRedirect || !/^\/\w/.test(options.authorizationRedirect)) {
    throw new Error(
      'options.authorizationRedirect should be a string'
    + ' in the format /api/oauth3/authorization_redirect'
    + ' Note that /:providerUri will be appended as an optional variable and'
    + ' the ?provider_uri=example.com query search parameter will also be honored'
    );
  }
  require('./router').create(app, routes);
};
