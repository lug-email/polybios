//jshint browser: true, maxstatements: 35
/*eslint no-use-before-define:0 */
/*global Polybios: true, openpgp:true, RemoteStorage: true, remoteStorage: true */
if (typeof window.Polybios === 'undefined') {
  window.Polybios = {};
}
(function () {
  "use strict";
  var wallet, store, mainPass = '', view, _;
  _ = document.webL10n.get;

  function onHash() {
    var hash   = window.location.hash.substr(1).split('/'),
        params = hash.slice(1);
    hash = hash[0];
    if (typeof view === 'undefined') {
      return;
    }
    if (hash === 'key' && params.length === 1) {
      view.keyDetail({dataset: { key: params[0] }});
    } else {
      if (typeof view[hash] === 'function') {
        view[hash]();
      }
    }
  }

  Polybios.Utils = {
    // Symetric encrypt
    symCrypt: function (pass, source) {
      pass = btoa(openpgp.crypto.hash.md5(pass));
      return btoa(openpgp.crypto.cfb.encrypt('', 'aes256', source, pass));
    },
    // Symetric decrypt
    symDecrypt: function (pass, source) {
      pass = btoa(openpgp.crypto.hash.md5(pass));
      return openpgp.crypto.cfb.decrypt('aes256', pass, atob(source));
    },
    settingsGet: function () {
      var settings = decodeURIComponent(document.cookie.replace(new RegExp("(?:(?:^|.*;)\\s*settings\\s*\\=\\s*([^;]*).*$)|^.*$"), "$1"));
      if (settings === '') {
        settings = {
          storeType: ''
        };
      } else {
        settings = JSON.parse(settings);
        if (typeof settings.useAct === 'undefined') {
          settings.useAct = false;
        }
        if (typeof settings.actServer === 'undefined') {
          settings.actServer = '';
        }
        if (typeof settings.lang === 'undefined') {
          settings.lang = 'en-us';
        }
      }
      return settings;
    },
    settingsSet: function (settings) {
      document.cookie = "settings=" + encodeURIComponent(JSON.stringify(settings)) + "; max-age=31536000";
    },
    settingsClear: function () {
      document.cookie = "settings=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    },
    initStore: function (settings) {
      function onStore(err, res) {
        var loadEvent;
        if (err) {
          if (err === 404) {
            console.log('No remote keyring found');
          } else {
            console.error(err);
          }
        }
        wallet = new openpgp.Keyring(store);
        view.setWallet(wallet);
        Polybios.walletLoaded = true;
        loadEvent = new CustomEvent("walletLoaded", {"detail": {action: "loaded"}});
        window.dispatchEvent(loadEvent);
        view.listKeys();
        window.wallet = wallet;
        onHash();
      }
      switch (settings.storeType) {
      case 'server':
        if (mainPass === '') {
          mainPass = window.prompt(_('msgMainPass'));
        }
        store = new PolybiosStore(onStore);
        break;
      case 'rs':
        if (mainPass === '') {
          mainPass = window.prompt(_('msgMainPass'));
        }
        // Init remoteStorage
        remoteStorage.access.claim('keystore', 'rw');
        remoteStorage.displayWidget();
        remoteStorage.on('connected', function () {
          console.log('connected');
          store = new RSStore(onStore);
        });
        break;
      case 'local':
        store = new openpgp.Keyring.localstore();
        onStore();
        break;
      case '':
        view.settings();
        break;
      default:
        view.message(_('msgUnknownStoreType'), 'error');
        view.settings();
        break;
      }
    }
  };

  function PolybiosStore(cb) {

    var self = this,
        xhr;
    this.storage = {};


    function loadKeys(type) {
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
    function storeKeys(type, keys) {
      var armoredKeys = [], i;
      for (i = 0; i < keys.length; i++) {
        armoredKeys.push(keys[i].armor());
      }
      self.storage[type] = armoredKeys;
    }

    this.loadPublic = function () {
      return loadKeys('public');
    };

    this.loadPrivate = function () {
      return loadKeys('private');
    };

    this.storePublic = function (keys) {
      storeKeys('public', keys);
    };

    this.storePrivate = function (keys) {
      storeKeys('private', keys);
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
      xhrPost.send(Polybios.Utils.symCrypt(mainPass, JSON.stringify(self.storage)));
    };


    try {
      xhr = new XMLHttpRequest();
      xhr.open('GET', 'store', true);
      xhr.onload = function () {
        if (xhr.status === 200) {
          try {
            self.storage = JSON.parse(Polybios.Utils.symDecrypt(mainPass, xhr.responseText));
          } catch (e) {
            self.storage = JSON.parse(xhr.responseText);
          }
          cb();
        } else if (xhr.status === 404) {
          self.storage = {
            public: [],
            private: []
          };
          cb(404);
        } else {
          cb('Error retrieving remote keyring');
        }
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        window.alert(err);
        cb(err);
      };
      xhr.send();
    } catch (e) {
      console.error(e);
      cb(e);
    }

  }

  function RSStore(cb) {

    var self = this;
    this.storage = {};

    function loadKeys(type) {
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
    function storeKeys(type, keys) {
      var armoredKeys = [], i;
      for (i = 0; i < keys.length; i++) {
        armoredKeys.push(keys[i].armor());
      }
      self.storage[type] = armoredKeys;
    }

    this.loadPublic = function () {
      return loadKeys('public');
    };

    this.loadPrivate = function () {
      return loadKeys('private');
    };

    this.storePublic = function (keys) {
      storeKeys('public', keys);
    };

    this.storePrivate = function (keys) {
      storeKeys('private', keys);
      remoteStorage.keystore.store(Polybios.Utils.symCrypt(mainPass, JSON.stringify(self.storage))).then(
        function () {
          console.log('Keyring stored');
        },
        function (err) {
          console.error(err);
          window.alert('Error saving wallet');
        }
      );
    };

    try {
      RemoteStorage.defineModule('keystore', function (privateClient, publicClient) {
        privateClient.declareType('store', {
          "description": "Keyring store",
          "type": "object",
          "properties": {
            "keyring": {
              "type": "string"
            }
          }
        });

        return {
          exports: {
            load: function () {
              return privateClient.getObject('store');
            },
            store: function (data) {
              return privateClient.storeObject('store', 'store', {
                keyring: data
              });
            }
          }
        };
      });

      remoteStorage.keystore.load().then(
        function (data) {
          if (typeof data === 'undefined') {
            self.storage = {
              public: [],
              private: []
            };
          } else {
            try {
              self.storage = JSON.parse(Polybios.Utils.symDecrypt(mainPass, data.keyring));
            } catch (e) {
              console.error("Unable to get storage");
              self.storage = {
                public: [],
                private: []
              };
            }
          }
          cb();
        },
        function (error) {
          self.storage = {
            public: [],
            private: []
          };
          cb(error);
        }
      );
    } catch (e) {
      console.error(e);
      cb(e);
    }

  }

  window.addEventListener("hashchange", onHash, false);

  window.addEventListener('load', function () {
    document.webL10n.ready(function () {
      var settings;
      function init() {
        view = new Polybios.UI();

        Polybios.Utils.initStore(settings);

        if (settings.useAct) {
          Polybios.Activity.init(settings);
        }
      }
      settings = Polybios.Utils.settingsGet();
      if (document.webL10n.getLanguage() !== settings.lang) {
        document.webL10n.setLanguage(settings.lang, init);
      } else {
        init();
      }
    });
  });

  // Fetch a key on keyserver
  function fetchKey(keyID, cb) {
    var req = new XMLHttpRequest();
    //req.open('GET', 'http://www.corsproxy.com/pgp.mit.edu/pks/lookup?op=get&search=0x' + keyID, true);
    req.open('GET', 'https://keys.whiteout.io/publickey/key/' + keyID, true);
    req.onreadystatechange = function () {
      if (req.readyState === 4) {
        if (req.status === 200) {
          cb(null, req.responseText);
        } else {
          cb(null, {message: 'Key not found', level: 'warning'});
        }
      }
    };
    req.send(null);
  }

  Polybios.PGP = {
    // Check message signature
    verify: function (message, cb) {
      //jshint maxstatements: 25
      function checkSignatures(msg) {
        function doCheck(msg1, key) {
          var pubKeys1 = {}, pubKeys2 = [];
          function format(pubkey) {
            var users = [];
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
          try {
            if (typeof key === 'string') {
              openpgp.key.readArmored(key).keys.forEach(format);
            } else {
              format(key);
            }
            msg1.verify(pubKeys2).forEach(function (verify) {
              var pubkeyId = verify.keyid.toHex(),
                  name     = pubkeyId.substr(-8).toUpperCase() + " " + pubKeys1[pubkeyId].userNames,
                  armored  = (typeof key === 'string' ? key : key.armor()),
                  signed;
              if (verify.valid === true) {
                signed = {
                  message: 'Good signature by key ' + name,
                  level: 'success',
                  key: armored,
                  data: msg.getLiteralData(),
                  text: msg.getText()
                };
                cb(null, signed);
              } else {
                cb(null, {message: 'Wrong signature by key ' + name, level: 'danger'});
              }
            });
          } catch (e) {
            cb(null, {message: 'Unable to check message signature', level: 'warning'});
            console.error(e);
          }
        }
        var keys;
        try {
          keys = msg.getSigningKeyIds();
          if (keys.length === 0) {
            cb(null, {message: 'No key found', level: 'warning'});
          } else {
            keys.forEach(function (keyID) {
              var key = null;
              keyID = keyID.toHex();
              if (wallet) {
                key = wallet.publicKeys.getForId(keyID);
              }
              if (key === null) {
                fetchKey(keyID, function (errFetch, resFetch) {
                  if (errFetch !== null) {
                    cb(errFetch, resFetch);
                  } else {
                    doCheck(msg, resFetch);
                  }
                });
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
      if (/^-----BEGIN PGP SIGNED MESSAGE/gm.test(message.text)) {
        checkSignatures(openpgp.cleartext.readArmored(message.text));
      } else if (/^-----BEGIN PGP MESSAGE/gm.test(message.text)) {
        checkSignatures(openpgp.message.readArmored(message.text));
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

  Polybios.KEYS = {
    passphrase: function (data, cb) {
      window.prompt(_('Passphrase'));
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
            view.listKeys();
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
            view.listKeys();
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
          dest: message.dest.join(','),
          type: 'sign'
        }
      };
      view.sign(node, message.text, cb);
    },
    decrypt: function (message, cb) {
      var node = {
        dataset: {
          type: 'decrypt'
        }
      };
      view.sign(node, message.text, cb);
    }
  };

  window.addEventListener('click', function (event) {
    var node   = event.target,
        action = event.target.dataset.action;
    while (node.parentNode && node.parentNode.dataset && typeof action === 'undefined') {
      node   = node.parentNode;
      action = node.dataset.action;
    }
    if (typeof action !== 'undefined' && typeof view[action] === 'function') {
      view[action](node);
    }
  });

}(window));
