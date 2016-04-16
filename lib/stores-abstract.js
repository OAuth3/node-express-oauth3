'use strict';

module.exports.create = function abstractFs(xconfx, requestOauth3Json) {
  var PromiseA = require('bluebird'); // deps.Promise;
  var inProcessCache = {};
  var path = require('path');

  function readJson(pathname) {
    var fs = PromiseA.promisifyAll(require('fs'));

    return fs.readdirAsync(pathname, 'utf8').then(function (text) {
      var reg;

      try {
        reg = JSON.parse(text);
      } catch(e) {
        reg = null;
      }

      return null;
    }, function (/*err*/) {
      return null;
    });
  }

  // TODO this belongs elsewhere
  function pruneDirectives(directives, len) {
    // prevent the directive list from growing infinitely long
    // (i.e. an attack)
    var leftovers = Object.keys(directives).filter(function (key) {
      // only remove dynamically discovered providers
      if (!directives[key].dynamic) {
        return false;
      }

      return true;
    }).sort(function (a, b) {
      // sort from least recently updated to most recently updated
      // i.e. [yesterday, today, 5 minutes ago, just now]
      return directives[b].updated - directives[a].updated;
    }).slice(len);
    directives.length = leftovers.length;
    leftovers.forEach(function (key) {
      // delete all of the old ones
      delete directives[key];
    });
  }

  var KeyStore = {
    create: function () {
      var ursa = require('ursa');
      var bits = 1024;
      var mod = 65537; // seems to be the most common, not sure why
      var key = ursa.generatePrivateKey(bits, mod);

      return key;
    }
  , getAsync: function (clientUri) {
      var fs = PromiseA.promisifyAll(require('fs'));
      var regpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', clientUri);

      return fs.readFileAsync(path.join(regpath, 'privkey.pem'), 'utf8').then(function (privkey) {
        return privkey;
      }, function () {
        var keypair = KeyStore.create();
        var privkey = keypair.toPrivatePem();

        return KeyStore.setAsync(clientUri, privkey).then(function () {
          return [ privkey ];
        });
      });
    }
  , setAsync: function (clientUri, privkey) {
      var fs = PromiseA.promisifyAll(require('fs'));
      var regpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', clientUri);

      return fs.writeFileAsync(path.join(regpath, 'privkey.pem'), privkey, 'utf8');
    }
  };

  var RegStore = {
    getAsync: function (hostnameUri, providerUri) {
      var regpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', hostnameUri);

      return readJson(path.join(regpath, providerUri + '.json')).then(function (reg) {
        if (!reg) {
          return PromiseA.reject(
            new Error("no on-device registration for '" + hostnameUri + "' with '" + providerUri + "'")
          );
        }
      });
    }
  , setAsync: function (hostnameUri, providerUri, reg) {
      var mkdirpAsync = PromiseA.promisify(require('mkdirp'));
      var fs = PromiseA.promisifyAll(require('fs'));
      var regpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', hostnameUri);

      return mkdirpAsync(regpath).then(function () {
        return fs.writeFileAsync(path.join(regpath, providerUri + '.json'), JSON.stringify(reg, null, '  '), 'utf8');
      });
    }
  };

  var DirStore = {
    getAsync: function (providerUri) {
      // TODO clusterify-fs
      // Example: etc/org.oauth3.consumer/cloud.example.com/oauth3.org.json
      var dirpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', 'providers', providerUri);

      return readJson(path.join(dirpath, providerUri + '.json')).then(function (reg) {
        if (!reg) {
          return PromiseA.reject(
            new Error("no local cache of directive for '" + providerUri + "'")
          );
        }
      });
    }
  , setAsync: function (providerUri, dir) {
      var mkdirpAsync = PromiseA.promisify(require('mkdirp'));
      var fs = PromiseA.promisifyAll(require('fs'));
      var dirpath = path.join(xconfx.etcpath, 'org.oauth3.consumer', 'providers', providerUri);

      return mkdirpAsync(dirpath).then(function () {
        return fs.writeFileAsync(path.join(dirpath, providerUri + '.json'), JSON.stringify(dir, null, '  '), 'utf8');
      });
    }
  };

  var DirCache = {
    getAsync: function (providerUri) {
      var dmeta = inProcessCache.directives[providerUri];
      var promise3;

      if (dmeta)  {
        promise3 = PromiseA.resolve(dmeta);
      }
      else {
        promise3 = DirStore.getAsync(providerUri).then(function (meta) {
          return meta;
        }, function () {
          return null;
        }).then(function (meta) {
          meta = meta || { expires: 0 };
          meta.tried = 0;
          meta.retryAfter = 0;
          return meta;
        });
      }

      return promise3.then(function (directiveMeta) {
        var promise;
        var now = Date.now();
        var fresh = directiveMeta.expires - now > 0;

        if (!fresh) {
          if (directiveMeta.tried >= 3 && directiveMeta.retryAfter - now > 0) {
            return PromiseA.reject(new Error("This server doesn't reply to oauth3.json and is in"
              + " cooldown for " + (directiveMeta.retryAfter - now / 1000).toFixed(0) + "s"));
          }
          // TODO how to reset tried to 0?
          directiveMeta.retryAfter = directiveMeta.retryAfter || (Date.now() + (5 * 60 * 1000));
          promise = requestOauth3Json(providerUri).then(function (result) {
            return DirCache.setAsync(providerUri, result);
          }, function (err) {
            return DirCache.errorAsync(providerUri, err);
          });
        }

        if (directiveMeta.directive) {
          promise = PromiseA.resolve(directiveMeta.directive);
        }

        return promise;
      });
    }
  , setAsync: function (providerUri, dir) {
      if (!inProcessCache.directives[providerUri]) {
        inProcessCache.directives.length += 1;
        // todo make length an option
        if (inProcessCache.directives.length >= 1000) {
          pruneDirectives(inProcessCache.directives, 100);
        }
      }

      inProcessCache.directives[providerUri] = {
        dynamic: true
      , updated: Date.now()
      , directive: dir
      , expires: Date.now() + (24 * 60 * 60 * 1000)
      , provider: providerUri
      , tried: 0
      , retryAfter: 0
      };

      return DirStore.setAsync(providerUri, inProcessCache.directives[providerUri]);
    }
  , errorAsync: function (providerUri) {
      var directiveMeta;

      if (!inProcessCache.directives[providerUri]) {
        inProcessCache.directives[providerUri] = {
          tried: 0
        , retryAfter: 0
        };
      }

      directiveMeta = inProcessCache.directives[providerUri];

      directiveMeta.tried += 1;

      if (!directiveMeta.directive) {
        return PromiseA.reject(new Error("could not get directive for '" + providerUri + "'"));
      }

      return directiveMeta.directive;
    }
  };

  return {
    DirStore: { getAsync: DirCache.getAsync }
  , RegStore: RegStore
  };
};
