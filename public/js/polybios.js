//jshint browser: true, maxstatements: 35, maxcomplexity: 12
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
          storeType: '',
          lang: 'en-us',
          useAct: false,
          actServer: '',
          devicePassword: ''
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
      function withMainpassDo(fct) {
        if (mainPass === '') {
          view.passphrase(_('msgMainPass'), _('templateSettingsPass'), function (err, pass) {
            if (err === null) {
              mainPass = pass;
              fct();
            }
          });
        } else {
          fct();
        }
      }
      function onStore(err, res) {
        var loadEvent;
        if (err) {
          if (err === 404) {
            view.message(_('msgStoreNoKeyring'), 'warning');
          } else {
            view.message(_('msgError') + ' ' + err, 'error');
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
        store = new PolybiosStore(onStore);
        break;
      case 'rs':
        // Init remoteStorage
        remoteStorage.access.claim('keystore', 'rw');
        remoteStorage.displayWidget();
        remoteStorage.on('connected', function () {
          withMainpassDo(function () {
            store = new RSStore(onStore);
          });
        });
        break;
      case 'local':
        withMainpassDo(function () {
          store = new openpgp.Keyring.localstore();
          onStore();
        });
        break;
      case 'cozy':
        withMainpassDo(function () {
          store = new CozyStore(onStore);
        });
        break;
      case '':
        view.message(_('msgNoStore'));
        view.settings();
        break;
      default:
        view.message(_('msgUnknownStoreType'), 'error');
        view.settings();
        break;
      }
    }
  };

  function DefaultStorage() {
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
            view.message(_('msgLoadkeysError') + ' ' + key.err, 'error');
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
      self.doSave();
    };

  }

  function PolybiosStore(cb) {
    var self = this,
        xhr;

    DefaultStorage.call(this);

    this.doSave = function () {
      var xhrPost = new XMLHttpRequest();
      xhrPost.open('POST', 'store', true);
      xhrPost.onload = function () {
        view.message(_('msgKeyringStored'));
      };
      xhrPost.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        view.message(_('msgKeyringStoreErr') + ' ' + err, 'error');
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
          cb(_('msgKeyringLoadErr'));
        }
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        view.message(_('msgKeyringLoadErr') + ' ' + err, 'error');
        cb(_('msgKeyringLoadErr') + ' ' + err);
      };
      xhr.send();
    } catch (e) {
      view.message(_('msgError') + ' ' + e, 'error');
      cb(_('msgError') + ' ' + e);
    }

  }

  function CozyStore(cb) {
    var self = this, cozy, password;

    DefaultStorage.call(this);

    this.doSave = function () {
      var data = {
        docType: 'PGPKeys',
        data: Polybios.Utils.symCrypt(mainPass, JSON.stringify(self.storage))
      };
      cozy.update('Polybios', data, function (err, res) {
        if (err === null) {
          view.message(_('msgKeyringStored'));
        } else {
          view.message(_('msgKeyringStoreErr') + ' ' + err, 'error');
        }
      });
    };

    function askCozyPassword() {
      view.passphrase(_('msgCozyPassword'), '', function (errPass, pass) {
        if (errPass === null) {
          password = pass;
          cozy = new window.Cozy('polybios', password, null, function (err, devicePassword) {
            setTimeout(function () {
              onCozy(err, devicePassword);
            }, 0);
          });
        }
      });
    }
    function onCozy(err, devicePassword) {
      if (err === null) {
        var settings = Polybios.Utils.settingsGet();
        settings.devicePassword = devicePassword;
        Polybios.Utils.settingsSet(settings);
        cozy.read('Polybios', function (readErr, res) {
          var data;
          if (readErr === null) {
            self.storage = JSON.parse(Polybios.Utils.symDecrypt(mainPass, res.data));
            cb();
          } else if (readErr === 404) {
            self.storage = {
              public: [],
              private: []
            };
            data = {
              docType: 'PGPKeys',
              data: Polybios.Utils.symCrypt(mainPass, JSON.stringify(self.storage))
            };
            cozy.create('Polybios', data, function (errCreate, resCreate) {
              if (errCreate === null) {
                cb();
              } else {
                view.message(_('msgKeyringStoreErr') + ' ' + errCreate, 'error');
                cb(_('msgKeyringLoadErr'));
              }
            });
          } else {
            cb(_('msgKeyringLoadErr'));
          }
        });
      } else {
        if (err === "Bad credentials") {
          view.message(_('msgCozyBadCredentials'), 'error');
          askCozyPassword();
        } else {
          cb(_('msgRegisterErr') + ' ' + err, 'error');
        }
      }
    }
    password = Polybios.Utils.settingsGet().devicePassword;
    if (password) {
      cozy = new window.Cozy('polybios', null, password, function (err, devicePassword) {
        setTimeout(function () {
          onCozy(err, devicePassword);
        }, 0);
      });
    } else {
      askCozyPassword();
    }
  }

  function RSStore(cb) {
    var self = this;

    DefaultStorage.call(this);

    this.doSave = function () {
      remoteStorage.keystore.store(Polybios.Utils.symCrypt(mainPass, JSON.stringify(self.storage))).then(
        function () {
          view.message(_('msgKeyringStored'));
        },
        function (err) {
          console.error(err);
          view.message(_('msgKeyringStoreErr') + ' ' + err, 'error');
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
              view.message(_('msgError') + ' ' + e, 'error');
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
      view.message(_('msgError') + ' ' + e, 'error');
      cb(_('msgError') + ' ' + e);
    }

  }

  window.addEventListener("hashchange", onHash, false);

  window.addEventListener('load', function () {
    var settings;
    settings = Polybios.Utils.settingsGet();
    // Wait for l10n to be ready
    function ready(callback) {
      if (document.webL10n.getReadyState === 'complete') {
        if (document.webL10n.getLanguage() !== settings.lang) {
          document.webL10n.setLanguage(settings.lang, callback);
        } else {
          callback();
        }
      } else {
        document.addEventListener('localized', function once() {
          document.removeEventListener('localized', once);
          if (document.webL10n.getLanguage() !== settings.lang) {
            document.webL10n.setLanguage(settings.lang, callback);
          } else {
            callback();
          }
        });
      }
    }
    ready(function () {
      view = new Polybios.UI();

      Polybios.Utils.initStore(settings);

      if (settings.useAct) {
        Polybios.Activity.init(settings);
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
          cb(null, {message: _('msgKeyNotFound', {id: keyID}), level: 'warning'});
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
                  message: _('msgSignatureOk', {name: name}),
                  level: 'success',
                  key: armored,
                  data: msg.getLiteralData(),
                  text: msg.getText()
                };
                cb(null, signed);
              } else {
                cb(null, {message: _('msgSignatureKo', {name: name}), level: 'danger'});
              }
            });
          } catch (e) {
            cb(null, {message: _('msgSignatureErr'), level: 'warning'});
            view.message(_('msgError') + ' ' + e, 'error');
          }
        }
        var keys;
        try {
          keys = msg.getSigningKeyIds();
          if (keys.length === 0) {
            cb(null, {message: _('msgSignatureNoKey'), level: 'warning'});
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
          cb(null, {message: _('msgSignatureErr') + ' ' + e, level: 'warning'});
          view.message(_('msgSignatureErr') + ' ' + e, 'error');
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
          cb(null, {message: _('msgSignatureErr') + ' ' + e, level: 'warning'});
          view.message(_('msgSignatureErr') + ' ' + e, 'error');
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
      view.passphrase(_('msgMainPass'), _('msgTemplateSettingsPass'), function (err, pass) {
        if (err === null) {
          mainPass = pass;
          cb(null, wallet);
        }
      });
    },
    importKey: function (message, cb) {
      var keys;
      function doImport(key) {
        var id = key.primaryKey.keyid.toHex().substr(-8).toUpperCase();
        if (key.isPublic()) {
          if (wallet.publicKeys.getForId(key.primaryKey.keyid.toHex()) === null) {
            wallet.publicKeys.push(key);
            wallet.store();
            view.listKeys();
            view.message(_('msgImportOk', {id: id}));
            cb(null, _('msgImportOk', {id: id}));
          } else {
            view.message(_('msgImportAlready', {id: id}));
            cb(null, _('msgImportAlready', {id: id}));
          }
        } else {
          if (wallet.privateKeys.getForId(key.primaryKey.keyid.toHex()) === null) {
            wallet.privateKeys.push(key);
            wallet.store();
            view.listKeys();
            view.message(_('msgImportOk', {id: id}));
            cb(null, _('msgImportOk', {id: id}));
          } else {
            view.message(_('msgImportAlready', {id: id}));
            cb(null, _('msgImportAlready', {id: id}));
          }
        }
      }
      if (typeof message === 'string') {
        keys = openpgp.key.readArmored(message);
        if (keys.keys.length > 0) {
          keys.keys.forEach(doImport);
        } else {
          cb(_('msgImportKo') + ' ' + keys.err.join("\n"));
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
    },
    addUser: function (key, pass, userId, cb) {
      console.log(key, pass, userId);
      //jshint bitwise: false
      var packetlist, userIdPacket, signaturePacket, dataToSign, secretPacket, newKey;
      if (!key.decrypt(pass)) {
        cb(_('msgWrongPassphrase'));
      } else {
        packetlist = new openpgp.packet.List();
        userIdPacket = new openpgp.packet.Userid();
        userIdPacket.read(userId);
        packetlist.push(userIdPacket);

        secretPacket = key.getSigningKeyPacket();
        if (!secretPacket.isDecrypted) {
          cb(_('msgWrongPassphrase'));
          console.error('Private key is not decrypted.');
        } else {
          packetlist.push(secretPacket);

          dataToSign = {};
          dataToSign.userid = userIdPacket;
          dataToSign.key    = secretPacket;
          signaturePacket   = new openpgp.packet.Signature();
          signaturePacket.signatureType      = openpgp.enums.signature.cert_generic;
          signaturePacket.publicKeyAlgorithm = secretPacket.algorithm;
          signaturePacket.hashAlgorithm      = openpgp.config.prefer_hash_algorithm;
          signaturePacket.keyFlags = [openpgp.enums.keyFlags.certify_keys | openpgp.enums.keyFlags.sign_data];
          signaturePacket.preferredSymmetricAlgorithms   = [openpgp.enums.symmetric.aes256, openpgp.enums.symmetric.aes192, openpgp.enums.symmetric.aes128, openpgp.enums.symmetric.cast5, openpgp.enums.symmetric.tripledes];
          signaturePacket.preferredHashAlgorithms        = [openpgp.enums.hash.sha256, openpgp.enums.hash.sha1, openpgp.enums.hash.sha512];
          signaturePacket.preferredCompressionAlgorithms = [openpgp.enums.compression.zlib, openpgp.enums.compression.zip];

          if (openpgp.config.integrity_protect) {
            signaturePacket.features = [];
            signaturePacket.features.push(1); // Modification Detection
          }
          signaturePacket.sign(secretPacket, dataToSign);
          packetlist.push(signaturePacket);
          newKey = openpgp.key.Key(packetlist);
          if (newKey) {
            key.update(newKey);
            cb(null, key);
          } else {
            cb(_('msgUserError'));
          }
        }
      }
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
