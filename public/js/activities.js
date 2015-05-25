//jshint browser: true
/*global Polybios: true */
if (typeof window.Polybios === 'undefined') {
  window.Polybios = {};
}
(function () {
  "use strict";
  var clear, options, manifest;
  clear = true; //@TODO
  function pgpHandler(message) {
    if (typeof Polybios.PGP[message.source.data.type] === 'function') {
      Polybios.PGP[message.source.data.type](message.source.data.data, function (err, res) {
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
    if (typeof Polybios.KEYS[message.source.data.type] === 'function') {
      Polybios.KEYS[message.source.data.type](message.source.data.data, function (err, res) {
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
      if (Polybios.walletLoaded === true) {
        doHandle();
      } else {
        window.addEventListener('walletLoaded', doHandle);
      }
    }
  }

  Polybios.Activity = {

    init: function (settings) {
      if (typeof window.Acthesis !== 'undefined') {
        options = {
          postMethod: 'message'
        };
        if (settings.actServer !== '') {
          options.server = settings.actServer;
        } else {
          // Some default values when installed on CozyCloud
          if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            options.server = 'http://localhost:9250';
          } else {
            options.server =  window.location.protocol + "//" + window.location.hostname + "/apps/acthesis";
          }
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
    }
  };
}());
