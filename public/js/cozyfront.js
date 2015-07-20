//jshint browser: true
(function (root) {
  "use strict";
  root.Cozy = function (appName, mainPassword, devicePassword, onCozy) {

    var _appName = appName,
        _mainPassword   = mainPassword,
        _devicePassword = devicePassword,
        self = this;


    /**
     * Register the application
     *
     * @param {Function} cb (err, password)
     *
     * @returns {null} null
     */
    this.registerApplication = function (cb) {
      var location, url, body, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/device';
      body = {
        login: _appName,
        permissions: {
          "PGPKeys": {
            "description": "Read and manage PGP keys"
          }
        }
      };
      xhr = new XMLHttpRequest();
      xhr.open('POST', url, true);
      xhr.onload = function () {
        var res;
        res = JSON.parse(xhr.response);
        if (res.password) {
          _devicePassword = res.password;
          cb(null, _devicePassword);
        } else if (res.error === "This name is already used") {
          self.updateApplication(cb);
        } else if (res.error === "Bad credentials") {
          cb("Bad credentials");
        }
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa("owner:" + _mainPassword));
      xhr.send(JSON.stringify(body));
    };

    /**
     * Get a new password for already registered application
     *
     * @param {Function} cb (err, password)
     *
     * @returns {null} null
     */
    this.updateApplication = function (cb) {
      var location, url, body, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/device/' + _appName;
      body = {
        login: _appName,
        permissions: {
          "PGPKeys": {
            "description": "Read and manage PGP keys"
          }
        }
      };
      xhr = new XMLHttpRequest();
      xhr.open('PUT', url, true);
      xhr.onload = function () {
        var res;
        res = JSON.parse(xhr.response);
        _devicePassword = res.password;
        cb(null, _devicePassword);
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa("owner:" + _mainPassword));
      xhr.send(JSON.stringify(body));
    };

    /**
     * Unregister current application
     *
     * @returns {null} null
     */
    this.unregisterApplication = function () {
      var location, url, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/device/' + _appName;
      xhr = new XMLHttpRequest();
      xhr.open('DELETE', url, true);
      xhr.onload = function () {
        console.log('ok');
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
      };
      xhr.setRequestHeader("Authorization", "Basic " + btoa("owner:" + _mainPassword));
      xhr.send();
    };

    this.create = function (id, data, cb) {
      var location, url, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/ds-api/data/';
      if (id !== null) {
        url += id + '/';
      }
      xhr = new XMLHttpRequest();
      xhr.open('POST', url, true);
      xhr.onload = function () {
        cb(null);
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa(_appName + ":" + _devicePassword));
      xhr.send(JSON.stringify(data));
    };

    this.read = function (id, cb) {
      var location, url, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/ds-api/data/' + id + '/';
      xhr = new XMLHttpRequest();
      xhr.open('GET', url, true);
      xhr.onload = function () {
        if (xhr.status === 200) {
          cb(null, JSON.parse(xhr.response));
        } else if (xhr.status === 404) {
          cb(404);
        } else {
          cb(xhr.status);
        }
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err, null);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa(_appName + ":" + _devicePassword));
      xhr.send();
    };

    this.update = function (id, data, cb) {
      var location, url, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/ds-api/data/' + id + '/';
      xhr = new XMLHttpRequest();
      xhr.open('PUT', url, true);
      xhr.onload = function () {
        cb(null);
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa(_appName + ":" + _devicePassword));
      xhr.send(JSON.stringify(data));
    };

    this.del = function (id, cb) {
      var location, url, xhr;
      location = window.location;
      url = location.protocol + '//' + location.host + '/ds-api/data/' + id + '/';
      xhr = new XMLHttpRequest();
      xhr.open('DELETE', url, true);
      xhr.onload = function () {
        cb(null);
      };
      xhr.onerror = function (e) {
        var err = "Request failed : " + e.target.status;
        console.error(err);
        cb(err);
      };
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("Authorization", "Basic " + btoa(_appName + ":" + _devicePassword));
      xhr.send();
    };

    if (!_devicePassword) {
      self.registerApplication(onCozy);
    } else {
      onCozy(null, _devicePassword);
    }
  };
}(window));
