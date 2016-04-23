'use strict';

var PromiseA = require('bluebird'); // deps.Promise;

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

function signRegistration(clientUri, privkey, providerUri, hostname, tos) {
  // TODO check options.clientUri and options.clientAgreeTos
  var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
  var crypto = require('crypto');
  var issuedAt = Math.floor(Date.now() / 1000);
  var expiresIn = (1 * 60 * 60);
  var expiresAt = Math.floor(new Date(Date.now() + (expiresIn * 1000)).valueOf() / 1000);
  var issuer = hostname; // the server issuing the redirect on behalf of the client
  var sha256 = require('crypto')
    .createHash('sha256')
    .update(privkey)
    .digest('base64')
    .replace(/=/g, '')
  ;

  // TODO
  // needs login identifier (grab from facebook, etc?)
  // needs account identifiers array (usually of one)

  // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1
  // https://openid.net/specs/draft-jones-json-web-token-07.html (prn became sub)
  // see org.oauth3.provider/oauthclient-microservice/lib/oauth3orize.js
  /* jwt = { jti, iss, aud, sub, typ, iat, exp, data } */
  return jwt.sign({
    jti: crypto.randomBytes(16).toString('hex') // prevent replays
  , iat: issuedAt             // IntDate
  , exp: expiresAt            // IntDate
  , kid: sha256               // the id of the key that signed this token

  , iss: 'https://' + issuer      // should this also be clientUri?
  , azp: 'https://' + clientUri
  , aud: 'https://' + providerUri

  , tos: tos

  , sub: clientUri // omit scheme
  , typ: 'registration'
  }, privkey, { algorithm: 'RS256' });
}

module.exports.create = function (DirStore, RegStore, KeyStore) {

  function registerClientHelper(dir, clientUri, providerUri, options) {
    var requestAsync = PromiseA.promisify(require('request'));

    // Note: client static site must have an oauth3.json with a directive pointing to api for public keys
    //console.log('DEBUG registerClientHelper', dir, hostnameUri, providerUri);

    return KeyStore.getAsync(clientUri).then(function (privkeys) {
      var privkey = privkeys[0]; // TODO how to choose a particular key
      var token = signRegistration(clientUri, privkey, providerUri, options.hostname, options.tos);

      return requestAsync({
        method: dir.registration.method
      , url: dir.registration.url
      , headers: {
          'Authorization': 'Bearer ' + token
        }
        /*
      , json: {
          clientUri: hostnameUri || options.clientUri
          // TODO need to get this from hostname uri
        , clientAgreeTos: 'oauth3.org/draft/tos' || options.clientAgreeTos
        , clientSignature: '{{sig}}' // rsasign(hash(clientAgreeTos))
        }
        */
      }).then(function (resp) {
        var data;
        var err;

        console.log('DEBUG register response');
        console.log(resp.body);

        try {
          data = JSON.parse(resp.body);
        } catch(e) {
          return PromiseA.reject(new Error("registration response could not be parsed: " + resp.body));
        }

        if (data.error) {
          err = new Error(data.error.message);
          err.code = 'E_REGISTRATION_FAIL';
          return PromiseA.reject(err);
        }

        return PromiseA.reject(new Error("Saving registration not implemented"));
      });
    });

    //return PromiseA.reject(new Error("oauth3 client registration not implemented"));
  }

  function fetchRegistration(dir, clientUri, providerUri, opts) {
    return RegStore.getAsync(dir, clientUri, providerUri).then(function (reg) {
      return reg;
    }, function () {
      return null;
    }).then(function (reg) {
      if (reg) {
        return reg;
      }

      if (!dir.registration) {
        return PromiseA.reject(new Error("'" + providerUri + "' does not support oauth3 automatic registration"));
      }

      return registerClientHelper(dir, clientUri, providerUri, opts);
    });
  }

  // TODO needs a hook for approval and limits on number of registrations
  var ConfigStore = {
    getAsync: function (clientUri, providerUri, opts) {
      //console.log('DEBUG ConfStore.getAsync', hostnameUri, providerUri);

      // TODO this should already be a normalized uri, so this shouldn't be necessary
      providerUri = providerUri.replace(/.*?:\/\//, '').replace(/\/$/, '');
      clientUri = clientUri.replace(/.*?:\/\//, '').replace(/\/$/, '');

      return DirStore.getAsync(providerUri).then(function (dir) {
        return dir;
      }, function (err) {
        return PromiseA.reject(
          new Error("Oauth3 could not retrieve oauth3.json for '" + encodeURI(providerUri) + "': " + err.message)
        );
      }).then(function (dir) {
        return fetchRegistration(dir, clientUri, providerUri, opts).then(function (reg) {
          return {
            directive: dir
          , registration: reg
          };
        }, function (err) {
          console.error(err.stack || err);
          return PromiseA.reject({
            message: err.message || err.error_description || err.toString()
          , code: err.code || "E_REGISTRATION"
          });
        });
      });
    }
  };

  return ConfigStore;
};
