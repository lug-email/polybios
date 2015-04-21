//jshint browser: true, maxstatements: 35
/*global openpgp:true */
(function (root) {
  "use strict";
  var clear, manifest, options, wallet, PGP, KEYS, UI, store;
  clear = true;

  function qsv(template) {
    return function (name, val) {
      var element = template.querySelector('[name="' + name + '"]');
      if (element && typeof val !== 'undefined') {
        element.textContent = val;
      }
      return element;
    };
  }
  function vars(template) {
    var res = {};
    Array.prototype.slice.call(template.querySelectorAll('[name]')).forEach(function (elmt) {
      res[elmt.getAttribute('name')] = elmt;
    });
    return res;
  }

  function getEnumValues(key) {
    var e = openpgp.enums[key], res = {};
    Object.keys(e).forEach(function (a, b) {
      res[b] = a;
    });
    return res;
  }

  function PolybiosStore(cb) {

    var self = this,
        xhr;
    this.storage = {};

    xhr = new XMLHttpRequest();
    xhr.open('GET', 'store', true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        self.storage = JSON.parse(xhr.responseText);
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
      if (armoredKeys !== null && armoredKeys.length !== 0) {
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
      xhrPost.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
      xhrPost.send(JSON.stringify(self.storage));
    };

  }

  store = new PolybiosStore(function (err, res) {
    var loadEvent;
    if (err) {
      console.error(err);
    } else {
      wallet = new openpgp.Keyring(store);
      loadEvent = new CustomEvent("walletLoaded", {"detail": {action: "loaded"}});
      window.dispatchEvent(loadEvent);
      UI.listKeys();
      window.wallet = wallet;
    }
  });

  function getDetailTemplate(key, showImport) {
    console.log(key);
    var template, $$, primary, importBtn;
    template = document.querySelector('#templates [data-template="keyDetail"]').cloneNode(true);
    $$ = qsv(template);
    primary = key.primaryKey;
    $$('armor', key.armor());
    $$('status', getEnumValues('keyStatus')[key.verifyPrimaryKey()]);
    $$('expiration', key.getExpirationTime() || 'never');
    $$('hash', openpgp.util.get_hashAlgorithmString(key.getPreferredHashAlgorithm()));
    $$('user', key.getPrimaryUser().user.userId.userid);
    $$('users', key.users.map(function (user) {
      if (user.userId) {
        return user.userId.userid + ' (' + getEnumValues('keyStatus')[user.verify(primary)] + ')';
      }
    }).join(', '));
    $$('public', key.isPublic());
    $$('algo', primary.algorithm);
    $$('created', primary.created.toString());
    $$('fingerprint', primary.fingerprint.toUpperCase().replace(/(....)/g, "$1 "));
    $$('id', primary.keyid.toHex().substr(-8).toUpperCase());
    $$('size', primary.getBitSize());
    if (key.isPrivate()) {
      $$('type', 'Private');
      $$('publicKey', key.toPublic().armor());
      template.classList.add('private');
    } else {
      $$('type', 'Public');
      template.classList.add('public');
    }
    // Image
    key.users.forEach(function (user) {
      var img;
      if (user.userAttribute) {
        img = document.createElement('img');
        img.src = 'data:image/jpeg;base64,' + btoa(user.userAttribute.write().substr(19));
        $$('photo').appendChild(img);
      }
    });
    // Signatures
    key.users.forEach(function (user) {
      if (user.userId) {
        var res = "<li>" + user.userId.userid + ' : ';
        if (Array.isArray(user.otherCertifications) && user.otherCertifications.length > 0) {
          user.otherCertifications.forEach(function (sig) {
            var issuer = sig.issuerKeyId.toHex().toUpperCase();
            //res += ' signed by <a href="http://pgp.mit.edu/pks/lookup?op=get&search=0x' + issuer + '" target="_blank">' + issuer + '</a>';
            res += ' signed by <a data-href="https://keys.whiteout.io/publickey/key/' + issuer + '" data-action="showRemoteKey" href="javascript:">' + issuer + '</a>';
            res += ' on ' + sig.created.toISOString();
            if (sig.trustLevel > 0 && sig.trustAmount > 119) {
              res += '(trusted)';
            }
            res += '; ';
          });
        } else {
          res += 'No signature\n';
        }
        res += "</li>\n";
        $$('sigs').innerHTML += res;
      }
    });
    template.dataset.key = primary.keyid.toHex();
    if (showImport) {
      importBtn = document.createElement('input');
      importBtn.setAttribute('type', 'button');
      importBtn.setAttribute('class', 'pure-button pure-button-primary');
      importBtn.value = 'Import';
      importBtn.addEventListener('click', function () {
        KEYS.importKey(key, function (err, res) {
          if (err) {
            console.error(err);
          } else {
            wallet.store();
            UI.listKeys();
          }
        });
      });
      $$('actions').appendChild(importBtn);
    }
    return template;
  }

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
      window.prompt('Passphrase');
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
            cb(null, "Imported public key " + id);
          } else {
            console.log("Key already in wallet");
            cb(null, "Key already in wallet");
          }
        } else {
          if (wallet.privateKeys.getForId(key.primaryKey.keyid.toHex()) === null) {
            wallet.privateKeys.push(key);
            console.log("Imported private key " + id);
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
          wallet.store();
          UI.listKeys();
        } else {
          cb("Enable to import keys : " + keys.err.join("\n"));
        }
      } else {
        doImport(message);
      }
    },
    sign: function (message, cb) {
      UI.sign(null, message.text, message.dest.join(','), cb);
    },
    decrypt: function (message, cb) {
      UI.sign(null, message.text, '', cb);
    }
  };

  UI = {
    /**
     * Generate a new private Key
     *
     * @param   {DOMElement} node target
     *
     * @returns {null} Nothing
     */
    generate: function (node) {
      var template, target, privateKey, $;
      function setSizeValue() {
        template.querySelector("[name='size-value']").textContent = template.querySelector("[name='size']").value;
      }
      template = document.querySelector('#templates [data-template="generate"]').cloneNode(true);
      target = document.getElementById('main');
      $ = vars(template);
      // @TODO Get account list
      //accounts = window.require('stores/account_store').getAll().toJS();
      //Object.keys(accounts).forEach(function (key) {
      //  var login = accounts[key].login;
      //  select += '<option value="' + login + '">' + login + '</option>';
      //});
      $.size.addEventListener('input', setSizeValue);
      setSizeValue();
      $.save.addEventListener('click', function (e) {
        wallet.privateKeys.push(privateKey);
        alert("Key added", privateKey);
        wallet.store();
        UI.listKeys();
        target.innerHTML = '';
      });
      $.generate.addEventListener('click', function (e) {
        $.generate.disabled = true;
        var keyOptions = {
          numBits: $.size.value,
          userId: '"' + $.username.value + '" <' + $.address.value + '>',
          passphrase: $.passphrase.value
        };
        openpgp.key.generate(keyOptions).then(function (key) {
          privateKey = key;
          $.key.textContent = key.armor();
          $.save.disabled = false;
          $.generate.textContent = 'Generate';
          $.generate.disabled = false;
        }).catch(function (err) {
          $.key.textContent = "Error: " + err;
          $.generate.textContent = 'Generate';
          $.generate.disabled = false;
        });
      });
      target.innerHTML = '';
      target.appendChild(template);
    },
    // UI.Import {{{
    'import': function (node) {
      var template, target, $;
      template = document.querySelector('#templates [data-template="import"]').cloneNode(true);
      $ = vars(template);
      target  = document.getElementById('main');
      function onError(xhrErr) {
        var err = "Request failed : " + xhrErr.target.status;
        console.error(err);
        $.key.value = 'ERROR: ' + err;
      }
      function viewKey() {
        $.importDetail.innerHTML = '';
        openpgp.key.readArmored($.key.value).keys.forEach(function (key) {
          var detail    = getDetailTemplate(key, true);
          $.importDetail.appendChild(detail);
        });
      }
      $.searchKeybase.addEventListener('click', function (e) {
        var xhr;
        xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://keybase.io/' + $.user.value + '/key.asc', true);
        xhr.onload = function () {
          if (xhr.status === 200) {
            $.key.value = xhr.responseText;
            viewKey();
          } else if (xhr.status === 404) {
            $.key.value = 'NOT FOUND';
          }
        };
        xhr.onerror = onError;
        xhr.send();
      });
      $.searchKeyserver.addEventListener('click', function (e) {
        var xhr;
        xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://subset.pool.sks-keyservers.net/pks/lookup?op=get&search=' + $.user.value, true);
        xhr.onload = function () {
          if (xhr.status === 200) {
            $.key.value = xhr.responseText;
            viewKey();
          } else if (xhr.status === 404) {
            $.key.value = 'NOT FOUND';
          }
        };
        xhr.onerror = onError;
        xhr.send();
      });
      $.searchWhiteout.addEventListener('click', function (e) {
        var xhr;
        xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://keys.whiteout.io/' + $.user.value, true);
        xhr.onload = function () {
          if (xhr.status === 200) {
            $.key.value = xhr.responseText;
            viewKey();
          } else if (xhr.status === 404) {
            $.key.value = 'NOT FOUND';
          }
        };
        xhr.onerror = onError;
        xhr.send();
      });
      $.view.addEventListener('click', viewKey);
      $.save.addEventListener('click', function (e) {
        KEYS.importKey($.key.value, function (err, res) {
          if (err) {
            console.error(err);
          } else {
            wallet.store();
            UI.listKeys();
          }
        });
      });
      target.innerHTML = '';
      target.appendChild(template);
    },
    // }}}
    // UI Sign {{{
    sign: function (node, text, dest, cb) {
      var template, target, $;
      template = document.querySelector('#templates [data-template="sign"]').cloneNode(true);
      $ = vars(template);
      target = document.getElementById('main');
      wallet.privateKeys.keys.forEach(function (key) {
        var option = document.createElement('option');
        key.getUserIds().forEach(function (user) {
          option.setAttribute('value', key.getKeyIds()[0].toHex());
          option.textContent = user;
          $.key.appendChild(option);
        });
      });
      $.message.value = text || '';
      $.dest.value    = dest || '';
      // Sign
      $.sign.addEventListener('click', function (e) {
        var privateKey, errors;
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push("Wrong passphrase");
        }
        if (errors.length === 0) {
          openpgp.signClearMessage(privateKey, $.message.value)
          .then(function (signed) {
            $.message.value = signed;
            if (typeof cb === 'function') {
              cb(null, signed);
            }
          })
          .catch(function (err) {
            console.error(err);
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          window.alert(errors.join(', '));
          cb(errors.join(', '));
        }
      });
      // Encrypt
      $.encrypt.addEventListener('click', function (e) {
        var keys = [], errors = [];
        $.dest.value.split(',').map(function (user) {
          var key = wallet.publicKeys.getForAddress(user.trim());
          key = key.concat(wallet.privateKeys.getForAddress(user.trim()));
          if (Array.isArray(key) && key.length > 0) {
            keys = keys.concat(key);
          } else {
            errors.push("No key for user " + user);
          }
        });
        if (errors.length === 0) {
          openpgp.encryptMessage(keys, $.message.value)
          .then(function (message) {
            $.message.value = message;
            if (typeof cb === 'function') {
              cb(null, message);
            }
          })
          .catch(function (err) {
            console.error(err);
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          window.alert(errors.join(', '));
          if (typeof cb === 'function') {
            cb(errors.join(', '));
          }
        }
      });
      // Sign and Encrypt
      $.signAndEncrypt.addEventListener('click', function (e) {
        var keys = [], errors = [], privateKey;
        $.dest.value.split(',').map(function (user) {
          var key = wallet.publicKeys.getForAddress(user.trim());
          key = key.concat(wallet.privateKeys.getForAddress(user.trim()));
          if (Array.isArray(key) && key.length > 0) {
            keys = keys.concat(key);
          } else {
            errors.push("No key for user " + user);
          }
        });
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push('Wrong passphrase');
        }
        if (errors.length === 0) {
          openpgp.signAndEncryptMessage(keys, privateKey, $.message.value)
          .then(function (message) {
            $.message.value = message;
            if (typeof cb === 'function') {
              cb(null, message);
            }
          })
          .catch(function (err) {
            console.error(err);
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          window.alert(errors.join(', '));
          if (typeof cb === 'function') {
            cb(errors.join(', '));
          }
        }
      });
      // Decrypt
      $.decrypt.addEventListener('click', function (e) {
        var privateKey, errors = [], armored, keys, res;
        armored = openpgp.message.readArmored($.message.value);
        keys = [];
        armored.getEncryptionKeyIds().forEach(function (keyid) {
          keys = keys.concat(wallet.getKeysForId(keyid.toHex(), true));
        });
        $.info.textContent = "Message encryted for " +
          keys.map(function (key) {
            return key.getPrimaryUser().user.userId.userid;
          }).join(', ');
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push('Wrong passphrase');
        }
        if (errors.length === 0) {
          res = armored.decrypt(privateKey);
          if (res) {
            $.message.value = res.getText();
            if (typeof cb === 'function') {
              cb(null, res.getText());
            }
          } else {
            errors.push('Unable to decrypt message');
            console.error(errors);
            window.alert(errors.join(', '));
            if (typeof cb === 'function') {
              cb(errors.join(', '));
            }
          }
        } else {
          console.error(errors);
          window.alert(errors.join(', '));
          if (typeof cb === 'function') {
            cb(errors.join(', '));
          }
        }

      });
      target.innerHTML = '';
      target.appendChild(template);
    },
    // }}}
    // UI.listKeys {{{
    listKeys: function (node) {
      var template, target, keys;
      target = document.getElementById('keysList');
      target.innerHTML = '';
      keys = wallet.getAllKeys();
      keys.forEach(function (key) {
        template = document.querySelector('#templates [data-template="keysList"]').cloneNode(true);
        //template.innerHTML += key.getKeyIds().map(function (id) {
        //  return id.toHex().substr(-8).toUpperCase();
        //}).join(', ');
        var primary = key.primaryKey;
        template.dataset.key = primary.keyid.toHex();
        template.innerHTML += ' ' + key.users.map(function (user) { if (user.userId) { return user.userId.userid; } }).join(', ');
        target.appendChild(template);
      });
    },
    // }}}
    // UI.keyDetail {{{
    keyDetail: function (node) {
      var target, keys;
      keys = wallet.getKeysForId(node.dataset.key, true);
      if (keys === null) {
        return;
      }
      target = document.getElementById('main');
      target.innerHTML = '';
      keys.forEach(function (key) {
        var removeBtn = document.createElement('input');
        removeBtn.setAttribute('type', 'button');
        removeBtn.setAttribute('class', 'pure-button pure-button-primary');
        removeBtn.value = 'Remove';
        removeBtn.addEventListener('click', function () {
          wallet.removeKeysForId(key.primaryKey.keyid.toHex());
          wallet.store();
          target.innerHTML = '';
          UI.listKeys();
        });
        target.appendChild(getDetailTemplate(key));
        qsv(target)('actions').appendChild(removeBtn);
      });
    },
    toggleOpen: function (e) {
      e.classList.toggle('closed');
    },
    showRemoteKey: function (node) {
      var xhr, res, closeBtn;
      xhr = new XMLHttpRequest();
      xhr.open('GET', node.dataset.href, true);
      xhr.onload = function () {
        if (xhr.status === 200) {
          res = getDetailTemplate(openpgp.key.readArmored(xhr.responseText).keys[0], true);
          closeBtn = document.createElement('input');
          closeBtn.setAttribute('type', 'button');
          closeBtn.setAttribute('class', 'pure-button pure-button-primary');
          closeBtn.value = 'close';
          res.appendChild(closeBtn);
          closeBtn.addEventListener('click', window.modal(res));
        } else if (xhr.status === 404) {
          res = 'NOT FOUND';
        }
      };
      xhr.onerror = function () {
        res = "Error fetching key";
      };
      xhr.send();
    }
    // }}}
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
  if (typeof window.Acthesis !== 'undefined') {
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
