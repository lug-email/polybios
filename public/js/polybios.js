//jshint browser: true, maxstatements: 35
/*global openpgp:true */
(function (root) {
  "use strict";
  var clear, manifest, options, wallet, PGP, KEYS, UI, store, mainPass, _, useActivities;
  clear = true;
  useActivities = true;
  _ = document.webL10n.get;

  function PolybiosStore(cb) {

    var self = this,
        xhr, symCrypt, symDecrypt;
    this.storage = {};

    // Symetric encrypt and decrypt
    symCrypt = function (pass, source) {
      pass = btoa(openpgp.crypto.hash.md5(pass));
      return btoa(openpgp.crypto.cfb.encrypt('', 'aes256', source, pass));
    };
    symDecrypt = function (pass, source) {
      pass = btoa(openpgp.crypto.hash.md5(pass));
      return openpgp.crypto.cfb.decrypt('aes256', pass, atob(source));
    };

    xhr = new XMLHttpRequest();
    xhr.open('GET', 'store', true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        try {
          self.storage = JSON.parse(symDecrypt(mainPass, xhr.responseText));
        } catch (e) {
          self.storage = JSON.parse(xhr.responseText);
        }
      } else if (xhr.status === 404) {
        self.storage = {
          public: [],
          private: []
        };
      }
      cb();
    };
    xhr.onerror = function (e) {
      var err = "Request failed : " + e.target.status;
      console.error(err);
      window.alert(err);
      cb(err);
    };
    xhr.send();


    function loadKeys(storage, type) {
      var armoredKeys = self.storage[type],
          keys = [], key, i;
      if (armoredKeys && armoredKeys.length !== 0) {
        for (i = 0; i < armoredKeys.length; i++) {
          key = openpgp.key.readArmored(armoredKeys[i]);
          if (!key.err) {
            keys.push(key.keys[0]);
          } else {
            console.error("Error reading armored key from keyring index: " + i);
          }
        }
      }
      return keys;
    }
    function storeKeys(storage, type, keys) {
      var armoredKeys = [], i;
      for (i = 0; i < keys.length; i++) {
        armoredKeys.push(keys[i].armor());
      }
      self.storage[type] = armoredKeys;
    }

    this.loadPublic = function () {
      return loadKeys(this.storage, 'public');
    };

    this.loadPrivate = function () {
      return loadKeys(this.storage, 'private');
    };

    this.storePublic = function (keys) {
      storeKeys(this.storage, 'public', keys);
    };

    this.storePrivate = function (keys) {
      storeKeys(this.storage, 'private', keys);
      var xhrPost = new XMLHttpRequest();
      xhrPost.open('POST', 'store', true);
      xhrPost.onload = function () {
        console.log('Keyring stored');
      };
      xhrPost.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        window.alert('Error saving wallet');
      };
      xhrPost.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
      xhrPost.send(symCrypt(mainPass, JSON.stringify(self.storage)));
    };

  }

  function onHash() {
    var hash   = window.location.hash.substr(1).split('/'),
        params = hash.slice(1);
    hash = hash[0];
    if (hash === 'key' && params.length === 1) {
      UI.keyDetail({dataset: { key: params[0] }});
    } else {
      if (typeof UI[hash] === 'function') {
        UI[hash]();
      }
    }
  }
  window.addEventListener("hashchange", onHash, false);

  window.addEventListener('localized', function () {
    mainPass = window.prompt(_('mainPass'));

    store = new PolybiosStore(function (err, res) {
      var loadEvent;
      if (err) {
        console.error(err);
      } else {
        wallet = new openpgp.Keyring(store);
        loadEvent = new CustomEvent("walletLoaded", {"detail": {action: "loaded"}});
        window.dispatchEvent(loadEvent);
        UI = new root.UI(KEYS, wallet);
        UI.listKeys();
        window.wallet = wallet;
        onHash();
      }
    });
  });

  PGP = {
    // Check message signature
    verify: function (message, cb) {
      //jshint maxstatements: 25
      function checkSignatures(msg) {
        function doCheck(msg1, key) {
          var pubKeys1 = {}, pubKeys2 = [];
          function format(pubkey) {
            var users = [];
            //debugger;
            pubkey.users.forEach(function (u) {
              if (typeof u.userId !== 'undefined' && u.userId !== null) {
                users.push(u.userId.userid);
              }
            });
            pubkey.userNames = users.join(', ');
            pubkey.getKeyIds().forEach(function (id) {
              pubKeys1[id.toHex()] = pubkey;
            });
            pubKeys2.push(pubkey);
          }
          if (typeof key === 'string') {
            openpgp.key.readArmored(key).keys.forEach(format);
          } else {
            format(key);
          }
          msg1.verify(pubKeys2).forEach(function (verify) {
            var pubkeyId = verify.keyid.toHex(),
                name     = pubkeyId.substr(-8).toUpperCase() + " " + pubKeys1[pubkeyId].userNames,
                armored  = (typeof key === 'string' ? key : key.armor());
            if (verify.valid === true) {
              cb(null, {message: 'Good signature by key ' + name, level: 'success', key: armored});
            } else {
              cb(null, {message: 'Wrong signature by key ' + name, level: 'danger'});
            }
          });
        }
        var keys;
        try {
          keys = msg.getSigningKeyIds();
          if (keys.length === 0) {
            cb(null, {message: 'No key found', level: 'warning'});
          } else {
            keys.forEach(function (keyID) {
              var key = null, req;
              keyID = keyID.toHex();
              if (wallet) {
                key = wallet.publicKeys.getForId(keyID);
              }
              if (key === null) {
                req = new XMLHttpRequest();
                //req.open('GET', 'http://www.corsproxy.com/pgp.mit.edu/pks/lookup?op=get&search=0x' + keyID, true);
                req.open('GET', 'https://keys.whiteout.io/publickey/key/' + keyID, true);
                req.onreadystatechange = function () {
                  if (req.readyState === 4) {
                    if (req.status === 200) {
                      try {
                        doCheck(msg, req.responseText);
                      } catch (e) {
                        cb(null, {message: 'Unable to check message signature', level: 'warning'});
                        console.error(e);
                      }
                    } else {
                      cb(null, {message: 'Key not found', level: 'warning'});
                    }
                  }
                };
                req.send(null);
              } else {
                doCheck(msg, key);
              }
            });
          }
        } catch (e) {
          cb(null, {message: 'Unable to check message signature', level: 'warning'});
          console.error(e);
        }
      }
      if (/^-----BEGIN PGP SIGNED MESSAGE/.test(message.text)) {
        checkSignatures(openpgp.cleartext.readArmored(message.text));
      } else {
        var re, headers = {}, boundary, res, parts, packetlist, literalDataPacket, input;
        message.headers['content-type'].split(/;\s+/).forEach(function (type) {
          if (/boundary/.test(type)) {
            boundary = type.split('=')[1].replace(/"|'/g, '')
                       // escape special chars
                       .replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
          }
        });
        try {
          re  = new RegExp("^." + boundary + ".*$", "gim");
          message.raw.split(/^--/gim)[0].replace(/\n\s+/gim, "").split(/\n/gim).forEach(function (h) {
            var tmp = h.split(':');
            if (tmp.length === 2) {
              headers[tmp[0].toLowerCase()] = tmp[1];
            }
          });
          res = /boundary=(.)([^\1]+?)\1/.exec(headers['content-type']);
          if (res && res.length === 3) {
            boundary = res[2].replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
          }
          re = new RegExp('\r{0,1}\n^-+' + boundary + '.*[\r|\n]+', 'gim');
          parts = message.raw.split(re).slice(1);
          packetlist = new openpgp.packet.List();
          literalDataPacket = new openpgp.packet.Literal();
          input = openpgp.armor.decode(parts[1]).data;
          literalDataPacket.setText(parts[0]);
          packetlist.push(literalDataPacket);
          packetlist.read(input);
          checkSignatures(new openpgp.message.Message(packetlist));
        } catch (e) {
          cb(null, {message: 'Unable to check message signature', level: 'warning'});
          console.error(e);
        }
        /*
        message.attachments.forEach(function (attach) {
          if (attach.contentType === 'application/pgp-signature') {
            cb({message: 'Checking pgp signature not implemented'});
          }
        });
        */
      }
    }
  };

  KEYS = {
    passphrase: function (data, cb) {
      window.prompt(_('Passphrase'));
      clear = true;
      cb(null, wallet);
    },
    importKey: function (message, cb) {
      var keys;
      function doImport(key) {
        var id = key.primaryKey.keyid.toHex().substr(-8).toUpperCase();
        if (key.isPublic()) {
          if (wallet.publicKeys.getForId(key.primaryKey.keyid.toHex()) === null) {
            wallet.publicKeys.push(key);
            console.log("Imported public key " + id);
            wallet.store();
            UI.listKeys();
            cb(null, "Imported public key " + id);
          } else {
            console.log("Key already in wallet");
            cb(null, "Key already in wallet");
          }
        } else {
          if (wallet.privateKeys.getForId(key.primaryKey.keyid.toHex()) === null) {
            wallet.privateKeys.push(key);
            console.log("Imported private key " + id);
            wallet.store();
            UI.listKeys();
            cb(null, "Imported private key " + id);
          } else {
            console.log("Key already in wallet");
            cb(null, "Key already in wallet");
          }
        }
      }
      if (typeof message === 'string') {
        keys = openpgp.key.readArmored(message);
        if (keys.keys.length > 0) {
          keys.keys.forEach(doImport);
        } else {
          cb("Enable to import keys : " + keys.err.join("\n"));
        }
      } else {
        doImport(message);
      }
    },
    sign: function (message, cb) {
      var node = {
        dataset: {
          dest: message.dest.join(',')
        }
      };
      UI.sign(node, message.text, cb);
    },
    decrypt: function (message, cb) {
      UI.sign(null, message.text, cb);
    }
  };


  function pgpHandler(message) {
    if (typeof PGP[message.source.data.type] === 'function') {
      PGP[message.source.data.type](message.source.data.data, function (err, res) {
        if (err) {
          message.postError(err);
        } else {
          message.postResult(res);
        }
      });
    } else {
      message.postError("WRONG ACTIVITY");
    }
  }
  function keysHandler(message) {
    if (typeof KEYS[message.source.data.type] === 'function') {
      KEYS[message.source.data.type](message.source.data.data, function (err, res) {
        if (err) {
          message.postError(err);
        } else {
          message.postResult(res);
        }
      });
    } else {
      message.postError("WRONG ACTIVITY");
    }
  }
  function handler(message) {
    console.log('HANDLER', message.source);
    function doHandle() {
      switch (message.source.name) {
        case 'pgp':
          pgpHandler(message);
          break;
        case 'pgpkeys':
          keysHandler(message);
          break;
        default:
          message.postError("WRONG ACTIVITY");
          break;
      }
    }
    if (!clear && message.source.name !== 'pgpkeys' && message.source.data.type !== 'passphrase') {
      message.postError({code: 401, message: "Unauthorized", source: message});
    } else {
      if (wallet) {
        doHandle();
      } else {
        window.addEventListener('walletLoaded', doHandle);
      }
    }
  }
  if (useActivities && typeof window.Acthesis !== 'undefined') {
    options = {
      postMethod: 'message'
    };
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      options.server = 'http://localhost:9250';
    } else {
      options.server =  window.location.protocol + "//" + window.location.hostname + "/apps/acthesis";
    }
    // We define 2 activities, because we need differents dispositions: some are hidden, others should be opened in new window
    manifest = {
      "activities": {
        "pgp": {
          "disposition": 'hidden',
          "returnValue": true
        },
        "pgpkeys": {
          "disposition": 'inline',
          "returnValue": true
        }
      }
    };
    window.Acthesis(options, manifest);
    navigator.mozSetMessageHandler('activity', handler);
    if (navigator.mozHasPendingMessage('activity')) {
      console.log("[provider] PENDING activities");
    } else {
      console.log("[provider] No pending activities");
    }
  }

  window.addEventListener('click', function (event) {
    var node   = event.target,
        action = event.target.dataset.action;
    while (node.parentNode && node.parentNode.dataset && typeof action === 'undefined') {
      node   = node.parentNode;
      action = node.dataset.action;
    }
    if (typeof action !== 'undefined' && typeof UI[action] === 'function') {
      UI[action](node);
    }
  });

}(window));
