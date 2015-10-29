'use strict';

module.exports.create = function (OAuth3Strategy, oauth3/*, options*/) {
  var querystring = require('querystring');
  var routes = {
    lint: function (req, res, next) {
      if (!req.query) {
        throw new Error('req.query must be parsed before authorizationRedirect is called');
      }
      if (!req.params) {
        throw new Error('req.params must be parsed before authorizationRedirect is called');
      }

      next();
    }
  , authorizationRedirect: function (req, res) {
      OAuth3Strategy.authorizationRedirect(oauth3, req).then(function (redirectUrl) {
        res.redirect(redirectUrl);
      }, function (err) {
        console.error('[Authenticate Error]');
        console.error(err.message);
        console.error(err.stack);
        // TODO reirect with error uri?
        res.send({
          error: err.code || err.message
        , error_description: err.message
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_0')
        });
      }).catch(function (err) {
        console.error('[UNKNOWN OAUTH3 EXCEPTION]');
        console.error(err.message);
        console.error(err.stack);
        res.send({
          error: 'E_UNEXPECTED_ERROR'
        , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_1')
        });
      });
    }
  , authorizationCodeCallback: function (req, res) {
      OAuth3Strategy.authorizationCodeCallback(oauth3, req).then(function (result) {
        res.redirect('/oauth3.html#' + querystring.stringify(result.params));
      }, function (err) {
        console.error('[Error Authenticate]');
        console.error(err.stack);

        // TODO reirect with error uri?
        res.send({
          error: err.code || err.message
        , error_description: err.message
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_2')
        });
      }).catch(function (err) {
        console.error('[UNKNOWN OAUTH3 EXCEPTION]');
        console.error(err.message);
        console.error(err.stack);
        res.send({
          error: 'E_UNEXPECTED_ERROR'
        , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_3')
        });
      });
    }
  };

  return routes;
};
