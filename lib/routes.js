'use strict';

module.exports.create = function (OAuth3Strategy, oauth3, options) {
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
        console.log('DEBUG authorizationRedirect res.redirect');
        res.redirect(redirectUrl);
      }, function (err) {
        console.error('[Authorization Redirect Error]');
        if (!err.stack) { console.error(err); }
        console.error(err.stack || new Error('getstack').stack);
        // TODO reirect with error uri?
        res.send({
          error: err.code || err.message
        , error_description: err.message
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_0')
        });
      }).catch(function (err) {
        console.error('[UNKNOWN OAUTH3 EXCEPTION]');
        if (!err.stack) { console.error(err); }
        console.error(err.stack || new Error('getstack').stack);
        res.send({
          error: 'E_UNEXPECTED_ERROR'
        , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_1')
        });
      });
    }
  , authorizationCodeCallback: function (req, res) {
      OAuth3Strategy.authorizationCodeCallback(oauth3, req).then(function (result) {
        // TODO [Standard] to allow mounted apps (example.com/mounted-app) or no (example.com)?
        // Currently there is no mechanism to know which mount an app came from as req.headers.origin is domain-only
        var baseUrl = (options.frontend || result.referer).replace(/\/$/, '');

        console.log('DEBUG authorizationCodeCallback res.redirect');
        res.redirect(baseUrl + '/oauth3.html#' + querystring.stringify(result.params));
      }, function (err) {
        console.error('[Error Authorization Code Callback]');
        if (!err.stack) { console.error(err); }
        console.error(err.stack || new Error('getstack').stack);

        // TODO redirect with error uri?
        res.send({
          error: err.code || err.message
        , error_description: err.message
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_2')
        });
      }).catch(function (err) {
        console.error('[UNKNOWN OAUTH3 EXCEPTION]');
        if (!err.stack) { console.error(err); }
        console.error(err.stack || new Error('getstack').stack);
        res.send({
          error: 'E_UNEXPECTED_ERROR'
        , error_description: "An unexpected error occurred. Check for code errors, database connection, and system errors."
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION_3')
        });
      });
    }
  , jwks: function (req, res) {
      var keyId = req.params.kid;

      return OAuth3Strategy.jwks(oauth3, req).then(function (keys) {
        var rsa = require('./rsa-utils');
        var result;

        console.log('DEBUG keys.length', keys.length);

        result = { keys: keys.map(function (privkey) {
          var sha256 = require('crypto')
            .createHash('sha256')
            .update(privkey)
            .digest('base64')
            .replace(/=/g, '')
          ;
          var privJwk = rsa.privPemToJwk(privkey);

          // http://connect2id.com/products/server/docs/config/jwk-set
          // https://tools.ietf.org/html/rfc7517#appendix-A.1
          return {
            alg: privJwk.alg || "RS256"
          , kty: privJwk.kty || "RSA"
          //, d: privJwk.d
          , e: privJwk.e
          , n: privJwk.n
          , kid: sha256
          };
        }) };

        if (keyId) {
          result.keys = result.keys.filter(function (k) {
            return keyId === k.kid;
          });
        }
        console.log('DEBUG result.keys', result.keys);
        res.send(result);
      }, function (err) {
        console.error('[Error JWKs]');
        if (!err.stack) { console.error(err); }
        console.error(err.stack || new Error('getstack').stack);

        // TODO redirect with error uri?
        res.send({
          error: err.code || err.message
        , error_description: err.message || err.toString()
        , error_uri: 'https://oauth3.org/docs/errors#' + (err.code || 'E_JWKS_EXCEPTION')
        });
      });
    }
  };

  return routes;
};
