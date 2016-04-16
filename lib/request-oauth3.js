'use strict';

var PromiseA = require('bluebird'); // deps.Promise;

function lintUrl(name, uri) {
  var url;
  var parsed;

  if (!uri) {
    throw (new Error("OAuth3 requires '" + encodeURIComponent(name) + "'."
      + " Ex: '&" + encodeURIComponent(name) + "=' + encodeURIComponent('https://example.com')"));
  }

  url = require('url');
  parsed = url.parse(uri);

  if ('http:' === parsed.protocol) {
    throw (new Error("OAuth3 requires an encrypted connection, but you provided a non-encrypted url."
      + " See https://letsencrypt.org for a free SSL certificate."));
  }

  if (('https:' !== parsed.protocol && 'spdy:' !== parsed.protocol) || !parsed.slashes) {
    throw (new Error("OAuth3 requires a full URI for '" + encodeURIComponent(name)
      + "', including the leading protocol https://"));
  }

  if (parsed.auth) {
    throw (new Error("OAuth3 requires that you do not supply a password when using Basic Authentication"
      + " (https://user:pass@example.com should be https://user@example.com) for '"
      + encodeURIComponent(name) + "'"
    ));
  }

  /*
  if ('/' !== uri[uri.length - 1]) {
    uri += '/';
  }
  */

  return uri;
}

function requestOauth3Json(uri) {
  var requestAsync = PromiseA.promisify(require('request'));
  // TODO limit size to prevent attack
  return requestAsync({ url: uri }).then(function (resp) {
    var json;

    try {
      json = JSON.parse(resp.body);
    } catch(e) {
      // ignore
      //console.error('oauth3.json parse error:');
      //console.error(resp.body);
      //console.error(e);
      return PromiseA.reject(new Error("Oauth3 could not parse '" + encodeURI(uri) + "' as valid json"));
    }

    // TODO lint urls and everything
    try {
      lintUrl('authorization_dialog', json.authorization_dialog.url);
    } catch(e) {
      e.message = "Bad oauth.json: authorization_dialog " + e.message;
      return PromiseA.reject(e);
    }
    try {
      lintUrl('access_token', json.access_token.url);
    } catch(e) {
      e.message = "Bad oauth.json: access_token " + e.message;
      return PromiseA.reject(e);
    }

    if ('string' !== typeof json.authn_scope) {
      return PromiseA.reject(new Error("Bad oauth.json: "
        + "authn_scope should be a string (even if it's an empty one)"));
    }
    try {
      lintUrl('profile', json.profile.url);
    } catch(e) {
      return PromiseA.reject(e);
    }
    /*
    try {
      lintUrl('accounts', json.authorization_dialog);
    } catch(e) {
      return PromiseA.reject(e);
    }
    */

    return json;
  });
}

function fetchDirectiveHelper(providerUri) {
  /*
  try {
    providerUri = lintUrl('provider_uri', providerUri);
  } catch(e) {
    return PromiseA.reject(e);
  }
  */

  function pass(data) {
    return data;
  }

  return requestOauth3Json('https://' + providerUri + '/.well-known/oauth3.json').then(pass, function (err) {
    return requestOauth3Json('https://' + providerUri + '/oauth3.json').then(pass, function () {
      // fallback to an oauth3 / oauth2 mapping service
      return requestOauth3Json('https://oauth3.org/providers/' + providerUri + '/oauth3.json').then(pass, function () {
        return requestOauth3Json('https://raw.githubusercontent.com/OAuth3/providers/master/' + providerUri + '.json');
      });
    });
  });
}
module.exports.getAsync = fetchDirectiveHelper;
