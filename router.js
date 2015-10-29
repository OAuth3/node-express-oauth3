'use strict';

module.exports.create = function (app, routes, config) {
  // debug only
  app.use(config.oauth3Prefix, routes.lint);

  // Authorization Code and Access Token
  app.get(config.authorizationRedirect + '/:providerUri?', routes.authorizationRedirect);
  app.get(config.authorizationCodeCallback + '/:providerUri?', routes.authorizationCodeCallback);
};
