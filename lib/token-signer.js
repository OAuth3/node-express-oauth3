'use strict';

module.exports.create = function (DirStore, KeyStore) {
  var PromiseA = require('bluebird'); // deps.Promise;
  var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));

  var TokenSigner = {
    // The purpose of this is essentially to establish a session
    signAsync: function (meta, params) {
      /* meta = { referer, host, scope, providerUri, browserState } */
      // TODO how to validate 3rd party approval? clientUri, clientAgreeTos?
      // https://tools.ietf.org/html/rfc6749#section-4.2.2
      /* params = { access_token, refresh_token, scope, state, token_type, expires_in, expires_at, expires (in) } */

      function getProfileUrl(resp) {
        var json = (resp.body || resp.data);

        console.log('resp.body', typeof resp.body);
        console.log('resp.data', typeof resp.data);
        if ('string' === typeof json) {
          json = JSON.parse(json);
        }

        if (!(json.profile || json.accounts)) {
          return PromiseA.reject({
            message: "no profile url"
          , code: "E_NO_OAUTH3_ACCOUNTS"
          });
        }

        return (json.profile || json.accounts);
      }

      function parseAccountIds(profileUrl) {
        var request = PromiseA.promisifyAll(require('request'));

        return request.getAsync(profileUrl).then(function (resp) {
          console.log('resp.body', typeof resp.body);
          console.log('resp.data', typeof resp.data);

          var json = (resp.body || resp.data);
          if ('string' === typeof json) {
            json = JSON.parse(json);
          }
          json = json.accounts || json.profile || json;

          if (Array.isArray(json)) {
            return json;
          }

          if (json.appScopedId || json.idx || json.id) {
            return [json];
          }

          // TODO need a way to specify where to grab oauth3.json in request
          return PromiseA.reject({
            message: "'" + meta.providerUrl + "' did not provide an id"
          , code: "E_NO_IDS"
          });
        });
      }

      /*
      function aggregateUsernamesAndEmails() {
        var emails = profiles.reduce(function (arr, profile) {
          if (profile.email) {
            arr.push(profile.email);
          }
          if (Array.isArray(profile.emails)) {
            profile.emails.forEach(function (email) {
              arr.push(email);
            });
          }
          return arr;
        }, []);
        var usernames = profiles.reduce(function (arr, profile) {
          if (profile.username) {
            arr.push(profile.username);
          }
          if (Array.isArray(profile.usernames)) {
            profile.usernames.forEach(function (username) {
              arr.push(username);
            });
          }
          return arr;
        }, []);
      }
      */

      // "https://facebook.com:765/yoyoy/?#" -> facebook.com/yoyoy
      var re = /(https?:\/\/)?([^:\/]+)(:\d+)?(\/[^#\?]+)?.*/;
      // we probably want to drop the port and any trailing junk after the last '/'
      var appname = (meta.referer || '').replace(re, '$2$4').replace(/\/$/, '');
      var appname2 = (meta.host || '').replace(re, '$2$4').replace(/\/$/, '');

      return DirStore.getAsync(meta.providerUri).then(getProfileUrl).then(parseAccountIds).then(function (profiles) {
        var crypto = require('crypto');
        var issuedAt = Math.floor(Date.now() / 1000);
        var audience = appname;
        var expiresIn = (1 * 60 * 60);
        var expiresAt = Math.floor(new Date(Date.now() + (expiresIn * 1000)).valueOf() / 1000);
        var issuer;
        var pub;

        // TODO need a way to describe app-scoped vs non-app-scoped ids
        // the accounts of one provider become ids for a consumer
        var ids = profiles.map(function (profile) {
          return profile.appScopedId || profile.idx || profile.id || profile;
        }).filter(function (p) { return p; });

        return KeyStore.getAsync(appname || appname2).then(function (keypair) {
          // TODO
          // needs login identifier (grab from facebook, etc?)
          // needs account identifiers array (usually of one)

          // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1
          // https://openid.net/specs/draft-jones-json-web-token-07.html (prn became sub)
          // see org.oauth3.provider/oauthclient-microservice/lib/oauth3orize.js
          /* jwt = { jti, iss, aud, sub, typ, iat, exp, data } */
          var accessToken = jwt.sign({
            jti: crypto.randomBytes(16).toString('hex') // prevent replays
          , iat: issuedAt             // IntDate
          , exp: expiresAt            // IntDate

          , iss: issuer               // the audience must trust the public keys of the issuer
          , aud: audience             // the issuer may have multiple audiences and therefore must specify (for the audience's sake)
          , sub: meta.providerUri     // rfc7519 for prn - the subject (principle) - in this case is the 3rd party login
          , typ: 'credentials'        // how to know what

          , data: params              // non-spec, application specific
          , pub: pub                  // non-spec TODO use a fingerprint of the keypair rather than the full public key pem

                                      // hmm... I'd really like to only have one id
          , ids: ids                  // non-spec TODO how can we know the ids are app-scoped?
          //, emails: emails
          //, usernames: usernames
          //, ixs: ixs                  // non-spec
          }, privkey, { algorithm: 'RS256' });

          // https://tools.ietf.org/html/rfc6749#section-4.2.2
          return {
          // The access token should have a lot of data (prevent db lookups)
            access_token: accessToken
          // The refresh token will require a database lookup (and check if the user is still allowed - PCI/SOX compliance)
          , refresh_token: '' // refreshToken
          // expires_at refers to accessToken, but since it's jwt
          , expires_at: expiresAt
          , expires_in: expiresIn
            // TODO declare what is granted with this token
          , scope: undefined
          , token_type: 'bearer'
          };
        });
      });
    }
  };

  return TokenSigner;
};
