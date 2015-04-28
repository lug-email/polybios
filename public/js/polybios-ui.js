//jshint browser: true, maxstatements: 35
/*global openpgp:true */
(function (root) {
  "use strict";
  var _;
  _ = document.webL10n.get;

  root.UI = function (KEYS, wallet) {
    var self = this;
    function Template(templateName) {
      var node, vars = {};
      node = document.querySelector('#templates [data-template="' + templateName + '"]').cloneNode(true);
      function qsv() {
        return function (name, val) {
          var element = node.querySelector('[name="' + name + '"]');
          if (element && typeof val !== 'undefined') {
            element.textContent = val;
          }
          return element;
        };
      }
      Array.prototype.slice.call(node.querySelectorAll('[name]')).forEach(function (elmt) {
        vars[elmt.getAttribute('name')] = elmt;
      });
      return {
        node: node,
        vars: vars,
        qsv: qsv(node)
      };
    }

    function getEnumValues(key) {
      var e = openpgp.enums[key], res = {};
      Object.keys(e).forEach(function (a, b) {
        res[b] = a;
      });
      return res;
    }

    function getDetailTemplate(key, showImport) {
      console.log(key);
      var template, primary, importBtn;
      function escapeAddress(user) {
        return user.userId.userid.replace(/[<>]/gim, function (c) { return '&#' + c.charCodeAt(0) + ';'; });
      }
      template = new Template('keyDetail');
      primary = key.primaryKey;
      template.qsv('armor', key.armor());
      template.qsv('status', getEnumValues('keyStatus')[key.verifyPrimaryKey()]);
      template.qsv('expiration', key.getExpirationTime() || 'never');
      template.qsv('hash', openpgp.util.get_hashAlgorithmString(key.getPreferredHashAlgorithm()));
      template.qsv('user', key.getPrimaryUser().user.userId.userid);
      template.vars.users.innerHTML = key.users.map(function (user) {
        if (user.userId) {
          return '<a href="javascript:" data-action="sign" data-type="encrypt" data-dest="' + user.userId.userid + '">' +
            escapeAddress(user) + ' (' + getEnumValues('keyStatus')[user.verify(primary)] + ')' +
            '</a>';
        }
      }).join(', ');
      template.qsv('public', key.isPublic());
      template.qsv('algo', primary.algorithm);
      template.qsv('created', primary.created.toString());
      template.qsv('fingerprint', primary.fingerprint.toUpperCase().replace(/(....)/g, "$1 "));
      template.qsv('id', primary.keyid.toHex().substr(-8).toUpperCase());
      template.qsv('size', primary.getBitSize());
      if (key.isPrivate()) {
        template.qsv('type', 'Private');
        template.qsv('publicKey', key.toPublic().armor());
        template.node.classList.add('private');
      } else {
        template.qsv('type', 'Public');
        template.node.classList.add('public');
      }
      // Image
      key.users.forEach(function (user) {
        var img;
        if (user.userAttribute) {
          img = document.createElement('img');
          img.src = 'data:image/jpeg;base64,' + btoa(user.userAttribute.write().substr(19));
          template.qsv('photo').appendChild(img);
        }
      });
      // Signatures
      key.users.forEach(function (user) {
        if (user.userId) {
          var res = "<li>" + escapeAddress(user) + ' : ';
          if (Array.isArray(user.otherCertifications) && user.otherCertifications.length > 0) {
            user.otherCertifications.forEach(function (sig) {
              var issuer = sig.issuerKeyId.toHex().toUpperCase();
              //res += ' signed by <a href="http://pgp.mit.edu/pks/lookup?op=get&search=0x' + issuer + '" target="_blank">' + issuer + '</a>';
              res += ' signed by <a data-href="https://keys.whiteout.io/publickey/key/' + issuer + '" data-action="showRemoteKey" href="javascript:">' + issuer.substr(-8) + '</a>';
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
          template.qsv('sigs').innerHTML += res;
        }
      });
      template.node.dataset.key = primary.keyid.toHex();
      if (showImport) {
        importBtn = document.createElement('input');
        importBtn.setAttribute('type', 'button');
        importBtn.setAttribute('class', 'pure-button pure-button-primary');
        importBtn.value = _('btnImport');
        importBtn.addEventListener('click', function () {
          KEYS.importKey(key, function (err, res) {
            if (err) {
              console.error(err);
            }
          });
        });
        template.qsv('actions').appendChild(importBtn);
      }
      return template.node;
    }

    /**
     * Generate a new private Key
     *
     * @param   {DOMElement} node target
     *
     * @returns {null} Nothing
     */
    this.generate = function (node) {
      document.getElementById('nav').classList.remove('active');
      var template, target, privateKey, $;
      function setSizeValue() {
        template.node.querySelector("[name='size-value']").textContent = template.node.querySelector("[name='size']").value;
      }
      template = new Template('generate');
      target = document.getElementById('main');
      $ = template.vars;
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
        self.listKeys();
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
      target.appendChild(template.node);
    };
    // UI.ImportKeys {{{
    this.importKeys = function (node) {
      document.getElementById('nav').classList.remove('active');
      var template, target, $;
      template = new Template('import');
      $ = template.vars;
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
          }
        });
      });
      target.innerHTML = '';
      target.appendChild(template.node);
    };
    // }}}
    // UI Sign {{{
    this.sign = function (node, text, cb) {
      document.getElementById('nav').classList.remove('active');
      var template, target, $;
      template = new Template('sign');
      $ = template.vars;
      if (node) {
        if (node.dataset.dest) {
          $.dest.value = node.dataset.dest;
        }
        if (node.dataset.type) {
          $.type.value = node.dataset.type;
        }
      }
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
      function getDests() {
        return $.dest.value.split(',').map(function (address) {
          address = address.trim();
          var res = /<([^>]*)>/.exec(address);
          if (res === null) {
            return address;
          } else {
            return res[1];
          }
        });
      }

      // Select type
      function onType() {
        template.node.dataset.type = $.type.value;
      }
      $.type.addEventListener('change', onType);
      onType();
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
        getDests().map(function (user) {
          var key = wallet.publicKeys.getForAddress(user);
          key = key.concat(wallet.privateKeys.getForAddress(user));
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
      $.full.addEventListener('click', function (e) {
        var keys = [], errors = [], privateKey;
        getDests().map(function (user) {
          var key = wallet.publicKeys.getForAddress(user);
          key = key.concat(wallet.privateKeys.getForAddress(user));
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
      target.appendChild(template.node);
    };
    // }}}
    // UI.listKeys {{{
    this.listKeys = function (node) {
      var target, keys, tmpKeys = [];
      target = document.getElementById('keysList');
      target.innerHTML = '';
      keys = wallet.getAllKeys();
      keys.forEach(function (key) {
        tmpKeys.push({
          id: key.primaryKey.keyid.toHex(),
          user: key.users[0].userId.userid
        });
      });
      tmpKeys.sort(function (a, b) {
        var u1 = a.user.toLowerCase().replace(/\W/g, ''),
            u2 = b.user.toLowerCase().replace(/\W/g, '');
        return u1 > u2 ? 1 : u1 > u2 ? -1 : 0;
      });
      tmpKeys.forEach(function (key) {
        var template = new Template('keysList');
        template.node.dataset.key = key.id;
        template.node.innerHTML = key.user;
        target.appendChild(template.node);
      });
    };
    // }}}
    // UI.keyDetail {{{
    this.keyDetail = function (node) {
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
        removeBtn.value = _('btnRemove');
        removeBtn.addEventListener('click', function () {
          wallet.removeKeysForId(key.primaryKey.keyid.toHex());
          wallet.store();
          target.innerHTML = '';
          self.listKeys();
        });
        target.appendChild(getDetailTemplate(key));
        target.querySelector('[name="actions"]').appendChild(removeBtn);
      });
    };
    this.toggleOpen = function (e) {
      e.classList.toggle('closed');
    };
    this.toggleMenu = function (node) {
      document.getElementById('nav').classList.toggle('active');
    };
    this.showRemoteKey = function (node) {
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
    };
    // }}}
  };
}(window));