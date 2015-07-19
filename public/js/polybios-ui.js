//jshint browser: true, maxstatements: 35
/*global openpgp:true, Polybios: true */
if (typeof window.Polybios === 'undefined') {
  window.Polybios = {};
}
(function () {
  "use strict";
  var _;
  _ = document.webL10n.get;

  // Copy content of a node into clipboard
  function toClipboard(node) {
    var sel, range;
    if (node.tagName.toLowerCase() === 'textarea') {
      node.focus();
      node.select();
    } else {
      sel = window.getSelection();
      sel.removeAllRanges();
      range = document.createRange();
      range.selectNode(node);
      sel.addRange(range);
    }
    document.execCommand('copy');
    sel.removeAllRanges();
  }

  Polybios.UI = function () {
    var self = this,
        wallet;

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

    function createButton(label) {
      var btn;
      btn = document.createElement('input');
      btn.setAttribute('type', 'button');
      btn.setAttribute('class', 'pure-button pure-button-primary');
      btn.value = label;
      return btn;
    }

    function escapeAddress(user) {
      return user.userId.userid.replace(/["<>]/gim, function (c) { return '&#' + c.charCodeAt(0) + ';'; });
    }

    function getDetailTemplate(key, showImport) {
      console.log(key);
      var template, primary, importBtn, $;
      template = new Template('keyDetail');
      $ = template.vars;
      primary = key.primaryKey;
      template.node.dataset.key = primary.keyid.toHex();

      // Details {{{
      $.armor.innerHTML = key.armor();
      template.qsv('status', getEnumValues('keyStatus')[key.verifyPrimaryKey()]);
      template.qsv('expiration', key.getExpirationTime() || 'never');
      template.qsv('hash', openpgp.util.get_hashAlgorithmString(key.getPreferredHashAlgorithm()));
      template.qsv('user', key.getPrimaryUser().user.userId.userid);
      $.users.innerHTML = key.users.map(function (user) {
        if (user.userId) {
          var escaped = escapeAddress(user),
              link    = '<a href="javascript:" data-action="sign" data-type="encrypt" data-dest="' + escaped + '">' +
                        escaped + ' (' + getEnumValues('keyStatus')[user.verify(primary)] + ')</a>';
          return link;
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
        $.publicKey.innerHTML = key.toPublic().armor();
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
      // }}}

      // Add user {{{
      $.addUser.addEventListener('click', function () {
        var userId;
        userId = '"' + $.newUserName.value + '" <' + $.newUserAddress.value + '>';
        Polybios.KEYS.addUser(key, $.passphrase.value, userId, function (err, newKey) {
          if (err === null) {
            self.message(_('msgUserAdded'), 'info');
            wallet.store();
            self.listKeys();
          } else {
            self.message(err, 'error');
          }
        });
      });

      // }}}
      // Signatures {{{
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
      // }}}

      // Import Button {{{
      if (showImport) {
        importBtn = document.createElement('input');
        importBtn.setAttribute('type', 'button');
        importBtn.setAttribute('class', 'pure-button pure-button-primary');
        importBtn.value = _('btnImport');
        importBtn.addEventListener('click', function () {
          Polybios.KEYS.importKey(key, function (err, res) {
            if (err) {
              console.error(err);
              self.message(err, 'error');
            }
          });
        });
        template.qsv('actions').appendChild(importBtn);
      }
      // }}}

      return template.node;
    }

    this.setWallet = function (w) {
      wallet = w;
    };

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
        self.message(_('msgKeyAdded', 'info'));
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
          $.generate.textContent = _('templateGenerateGenerate');
          $.generate.disabled = false;
        }).catch(function (err) {
          $.key.textContent = "Error: " + err;
          $.generate.textContent = _('templateGenerateGenerate');
          $.generate.disabled = false;
        });
      });
      target.innerHTML = '';
      target.appendChild(template.node);
      self.toggleDetail(true);
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
        self.message(_('msgImportError'), 'error');
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
        Polybios.KEYS.importKey($.key.value, function (err, res) {
          if (err) {
            console.error(err);
            self.message(err, 'error');
          }
        });
      });
      $.importFile.addEventListener('change', function importFile(ev) {
        var reader, i, numFiles;
        reader = new FileReader();
        reader.onload = function (e) {
          Polybios.KEYS.importKey(e.target.result, function (err, res) {
            if (err) {
              console.error(err);
              self.message(err, 'error');
            }
          });
        };
        for (i = 0, numFiles = ev.target.files.length; i < numFiles; i++) {
          reader.readAsText(ev.target.files[i]);
        }
      });
      target.innerHTML = '';
      target.appendChild(template.node);
      self.toggleDetail(true);
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
      // empty key
      (function () {
        var option = document.createElement('option');
        option.setAttribute('value', '');
        option.textContent = '';
        $.key.appendChild(option);
      }());
      // Add all private keys
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
      // Cancel
      $.cancel.addEventListener('click', function (e) {
        target.innerHTML = '';
        if (typeof cb === 'function') {
          cb('User canceled', null);
        }
      });
      // Sign
      $.sign.addEventListener('click', function (e) {
        var privateKey, errors = [];
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push(_('msgWrongPassphrase'));
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
            self.message(_('msgSignError') + err, 'error');
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          self.message(errors.join("<br>\n"), 'error');
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
            errors.push(_('msgNoKeyForUser') + user);
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
            self.message(_('msgEncryptError') + err, 'error');
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          self.message(errors.join("<br>\n"), 'error');
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
            errors.push(_('msgNoKeyForUser') + user);
          }
        });
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push(_('msgWrongPassphrase'));
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
            self.message(_('msgEncryptError') + err, 'error');
            if (typeof cb === 'function') {
              cb(err);
            }
          });
        } else {
          console.error(errors);
          self.message(errors.join("<br>\n"), 'error');
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
        $.info.textContent = _('msgEncryptedFor') +
          keys.map(function (key) {
            return key.getPrimaryUser().user.userId.userid;
          }).join(', ');
        if ($.key.value === '') {
          return;
        }
        privateKey = wallet.privateKeys.getForId($.key.value);
        if (!privateKey.decrypt($.passphrase.value)) {
          errors.push(_('msgWrongPassphrase'));
        }
        if (errors.length === 0) {
          res = armored.decrypt(privateKey);
          if (res) {
            $.message.value = res.getText();
            if (typeof cb === 'function') {
              cb(null, res.getText());
            }
          } else {
            errors.push(_('msgDecryptError'));
            self.message(errors.join("<br>\n"), 'error');
            if (typeof cb === 'function') {
              cb(errors.join(', '));
            }
          }
        } else {
          console.error(errors);
          self.message(errors.join("<br>\n"), 'error');
          if (typeof cb === 'function') {
            cb(errors.join(', '));
          }
        }

      });
      // Verify
      $.verify.addEventListener('click', function (e) {
        var message;
        message = {
          text: $.message.value
        };
        Polybios.PGP.verify(message, function (err, res) {
          if (err) {
            $.info.textContent = _('msgVerifyError');
          } else {
            $.info.innerHTML = "<p>" + res.message + "</p>\n";
            if (res.data) {
              $.info.innerHTML += "<p><em>Data</em></p>\n<p>" + res.data + "</p>\n";
            }
            if (res.text) {
              $.info.innerHTML += "<p><em>Text</em></p>\n<p>" + res.text + "</p>\n";
            }
          }
          console.log(err, res);
        });
      });
      target.innerHTML = '';
      target.appendChild(template.node);
      self.toggleDetail(true);
    };
    // }}}
    this.verify = function (node, text, cb) {
      if (typeof node === 'undefined') {
        node = {
          dataset: {}
        };
      }
      if (typeof node.dataset.type === 'undefined') {
        node.dataset.type = 'verify';
      }
      this.sign(node, text, cb);
    };
    // UI.listKeys {{{
    this.listKeys = function (node) {
      var target, keys, tmpKeys = [];
      target = document.getElementById('keysList');
      target.innerHTML = '';
      keys = wallet.getAllKeys();
      keys.forEach(function (key) {
        tmpKeys.push({
          id: key.primaryKey.keyid.toHex(),
          user: key.users[0].userId.userid,
          priv: key.isPrivate()
        });
      });
      tmpKeys.sort(function (a, b) {
        var u1 = a.user.toLowerCase().replace(/\W/g, ''),
            u2 = b.user.toLowerCase().replace(/\W/g, '');
        return u1 > u2 ? 1 : u1 > u2 ? -1 : 0;
      });
      tmpKeys.forEach(function (key) {
        var template = new Template('keysList');
        template.node.dataset.key   = key.id;
        if (key.priv) {
          template.node.classList.add('private');
        }
        template.vars.listItem.href = '#key/' + key.id;
        template.vars.listItem.textContent = key.user;
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
        var actions, removeBtn, exportBtn;
        target.appendChild(getDetailTemplate(key));
        removeBtn = createButton(_('btnRemove'));
        removeBtn.addEventListener('click', function () {
          wallet.removeKeysForId(key.primaryKey.keyid.toHex());
          wallet.store();
          target.innerHTML = '';
          self.listKeys();
        });
        exportBtn = createButton(_('btnExport'));
        exportBtn.addEventListener('click', function () {
          var blob, a;
          blob = new Blob([key.armor()], {type: "text/plain"});
          a = document.createElement('a');
          a.download    = "key.asc";
          a.href        = window.URL.createObjectURL(blob);
          a.textContent = "Download backup.json";
          a.dispatchEvent(new window.MouseEvent('click', { 'view': window, 'bubbles': true, 'cancelable': true }));
        });
        actions = target.querySelector('[name="actions"]');
        actions.appendChild(removeBtn);
        actions.appendChild(exportBtn);
        key.users.map(function (user) {
          var encryptBtn;
          if (user.userId) {
            encryptBtn = createButton(_('btnEncrypt', {user: user.userId.userid}));
            encryptBtn.addEventListener('click', function () {
              self.sign({dataset: {type: 'encrypt', dest: user.userId.userid}});
            });
            actions.appendChild(encryptBtn);
          }
        });
      });
      self.toggleDetail(true);
    };
    // UI Settings {{{
    this.settings = function () {
      document.getElementById('nav').classList.remove('active');
      var template, target, $, settings;
      template = new Template('settings');
      $ = template.vars;
      $.save.addEventListener('click', function () {
        var s = Polybios.Utils.settingsGet();
        s.storeType = $.type.value;
        s.useAct    = $.useAct.checked;
        s.actServer = $.actServer.value;
        s.lang      = $.lang.value;
        Polybios.Utils.settingsSet(s);
        Polybios.Utils.initStore(s);
        self.message(_('msgSettingsSaved'));
      });
      $.type.addEventListener('change', function () {
        template.node.dataset.type = this.value;
        var s = Polybios.Utils.settingsGet();
        s.storeType = this.value;
        $.storeHelp.innerHTML = _('msgHelpStore' + this.value.replace(/^./, function (a) {return a.toUpperCase(); }));
        Polybios.Utils.settingsSet(s);
        Polybios.Utils.initStore(s);
        self.message(_('msgSettingsSaved'));
      });
      $.lang.addEventListener('change', function () {
        var s = Polybios.Utils.settingsGet();
        s.lang = this.value;
        Polybios.Utils.settingsSet(s);
        document.webL10n.setLanguage(this.value, function () {
          self.message(_('msgSettingsSaved'));
        });
      });
      $.useAct.addEventListener('change', function () {
        template.node.dataset.type = this.value;
        var s = Polybios.Utils.settingsGet();
        s.useAct = this.checked;
        Polybios.Utils.settingsSet(s);
        self.message(_('msgSettingsSaved'));
      });
      $.actServer.addEventListener('change', function () {
        template.node.dataset.type = this.value;
        var s = Polybios.Utils.settingsGet();
        s.actServer = this.value;
        Polybios.Utils.settingsSet(s);
        self.message(_('msgSettingsSaved'));
      });
      settings = Polybios.Utils.settingsGet();
      $.type.value      = settings.storeType;
      $.lang.value      = settings.lang;
      $.useAct.checked  = settings.useAct;
      $.actServer.value = settings.actServer || '';
      $.storeHelp.innerHTML = _('msgHelpStore' + settings.storeType.replace(/^./, function (a) {return a.toUpperCase(); }));
      target = document.getElementById('main');
      target.innerHTML = '';
      target.appendChild(template.node);
      self.toggleDetail(true);
    };
    // Settings }}}
    this.toggleOpen = function (e) {
      e.classList.toggle('closed');
    };
    this.toggleMenu = function (node) {
      document.getElementById('nav').classList.toggle('active');
    };
    this.toggleDetail = function (detail) {
      if (detail === true) {
        document.getElementById('list').classList.remove('active');
        document.getElementById('main').classList.add('active');
      } else {
        document.getElementById('list').classList.toggle('active');
        document.getElementById('main').classList.toggle('active');
      }
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
    this.message = function (text, level) {
      var elmt, hide, to;
      if (typeof level === 'undefined') {
        level = 'info';
      }
      elmt = document.getElementById('message');
      hide = function () {
        window.clearTimeout(to);
        elmt.classList.remove('active');
        elmt.innerHTML = '';
      };
      if (typeof text === 'string') {
        elmt.innerHTML = text;
        elmt.dataset.level  = level;
        elmt.classList.add('active');
        if (level === 'info') {
          to = window.setTimeout(hide, 2000);
        }
      } else {
        hide();
      }
    };
    this.toClipboard = function (node) {
      var parent = node.parentNode,
          target;
      while (parent && parent.tagName && parent.tagName.toLowerCase() !== 'form' && !parent.dataset.template) {
        parent = parent.parentNode;
      }
      console.log(parent);
      if (parent) {
        target = parent.querySelector("[name='" + node.dataset.target + "']");
        if (target) {
          toClipboard(target);
        }
      }
    };
    // Display a modal to ask a password
    this.passphrase = function (title, label, cb) {
      var template, modal;
      template = new Template('passphrase');
      modal    = window.modal(template.node);
      template.vars.title.innerHTML = title;
      template.vars.label.innerHTML = label;
      template.vars.save.addEventListener('click', function () {
        cb(null, template.vars.pass.value);
        modal();
      });
    };
    // }}}
  };
}());
