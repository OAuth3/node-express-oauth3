'use strict';

module.exports.create = function (app, routes, config) {
  // debug only
  if ((config.oauth3PrefixInternal || config.oauth3Prefix) && routes.lint) {
    app.use((config.oauth3PrefixInternal || config.oauth3Prefix), routes.lint);
  }

  // Authorization Code and Access Token
  app.get(config.authorizationRedirect + '/:providerUri?', routes.authorizationRedirect);
  app.get(config.authorizationCodeCallback + '/:providerUri?', routes.authorizationCodeCallback);

  return app;
};
