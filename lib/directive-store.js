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

module.exports.create = function (DirStore, RegStore) {
  function registerClientHelper(dir, hostnameUri, providerUri) {
    // Note: client static site must have an oauth3.json with a directive pointing to api for public keys
    console.log('DEBUG registerClientHelper', dir, hostnameUri, providerUri);
    return PromiseA.reject(new Error("oauth3 client registration not implemented"));
  }

  function fetchRegistration(dir, hostnameUri, providerUri) {
    return RegStore.getAsync(dir, hostnameUri, providerUri).then(function (reg) {
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

      return registerClientHelper(dir, hostnameUri, providerUri);
    });
  }

  // TODO needs a hook for approval and limits on number of registrations
  var ConfigStore = {
    getAsync: function (hostnameUri, providerUri) {
      console.log('DEBUG', hostnameUri, providerUri);

      // TODO this should be a normalized uri, so this shouldn't be necessary
      providerUri = providerUri.replace(/.*?:\/\//, '').replace(/\/$/, '');
      hostnameUri = hostnameUri.replace(/.*?:\/\//, '').replace(/\/$/, '');

      return DirStore.getAsync(providerUri).then(function (dir) {
        return dir;
      }, function (err) {
        return PromiseA.reject(
          new Error("Oauth3 could not retrieve oauth3.json for '" + encodeURI(providerUri) + "': " + err.message)
        );
      }).then(function (dir) {
        return fetchRegistration(dir, hostnameUri, providerUri).then(function (reg) {
          return {
            directive: dir
          , registration: reg
          };
        }, function (err) {
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
