'use strict';

function binstrToB64(binstr) {
  return new Buffer(binstr, 'binary').toString('base64');
}

function privPemToJwk(privPem) {
  var forge = require('node-forge');
  var forgePrivkey = forge.pki.privateKeyFromPem(privPem);

  Object.keys(forgePrivkey).forEach(function (k) {
    var val = forgePrivkey[k];
    if (val && val.toByteArray) {
      forgePrivkey[k] = val.toByteArray();
    }
  });

  return {
    kty: "RSA"
  , n: binstrToB64(forgePrivkey.n)
  , e: binstrToB64(forgePrivkey.e)
  , d: binstrToB64(forgePrivkey.d)
  , p: binstrToB64(forgePrivkey.p)
  , q: binstrToB64(forgePrivkey.q)
  , dp: binstrToB64(forgePrivkey.dP)
  , dq: binstrToB64(forgePrivkey.dQ)
  , qi: binstrToB64(forgePrivkey.qInv)
  };
}

module.exports.privPemToJwk = privPemToJwk;
