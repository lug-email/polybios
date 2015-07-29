//jshint node: true
(function () {
  "use strict";
  var connect     = require('connect'),
      http        = require('http'),
      bodyParser  = require('body-parser'),
      serveStatic = require('serve-static'),
      fs          = require('fs'),
      path        = require('path'),
      app, port, host, store, storeType, cozydb;

  process.on('uncaughtException', function (err) {
    console.error("Uncaught Exception");
    console.error(err);
    console.error(err.stack);
  });

  port = process.env.PORT || 9253;
  host = process.env.HOST || "127.0.0.1";

  app = connect();

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.text({limit: '10mb'}));

  /*
   * store keyring on the filesystem
   */
  function FileStore() {
    var storePath = path.join(__dirname, '/store');
    function get(req, res) {
      fs.stat(storePath, function (errStat, stats) {
        if (errStat || typeof stats === 'undefined') {
          res.statusCode = 404;
          res.end('');
        } else {
          res.statusCode = 200;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          fs.createReadStream(storePath).pipe(res);
        }
      });
    }
    function set(req, res) {
      fs.writeFile(storePath, req.body, function (err) {
        fs.chmod(storePath, '600');
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        if (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({res: err}));
        } else {
          res.statusCode = 200;
          res.end(JSON.stringify({res: 'ok'}));
        }
      });
    }
    return {
      get: get,
      set: set
    };
  }

  /*
   * Store keyring into CozyCloud DataSystem
   */
  function CozyStore() {
    var Model, modelOptions, id;

    modelOptions = {
      keyring: {
        'type': String,
        'default': ''
      }
    };
    Model = cozydb.getModel('keyring', modelOptions);
    Model.defineRequest('all', cozydb.defaultRequests.all, function (err) {
      if (err) {
        console.error("Error defining request:", err);
      }
    });
    function get(req, res) {
      Model.all(function (err, data) {
        if (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({res: err}));
        } else if (data.length === 0) {
          res.statusCode = 404;
          res.end('');
        } else {
          res.statusCode = 200;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          id = data[0]._id;
          res.end(data[0].keyring);
        }
      });
    }
    function set(req, res) {
      var data = { docType: 'keyring', keyring: req.body };
      function onSaved(err, result) {
        console.log(err, result);
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        if (err) {
          res.statusCode = 500;
          res.end(JSON.stringify({res: err}));
        } else {
          if (result._id) {
            id = result._id;
          }
          res.statusCode = 200;
          res.end(JSON.stringify({res: 'ok'}));
        }
      }
      if (id) {
        Model.updateAttributes(id, data, onSaved);
      } else {
        Model.create(data, onSaved);
      }
    }
    return {
      get: get,
      set: set
    };
  }

  try {
    cozydb = require("cozydb");
    store = new CozyStore();
    storeType = 'cozy';
    console.log("Using CozyDB store");
  } catch (e) {
    if (e instanceof Error && e.code === "MODULE_NOT_FOUND") {
      console.log("Using file store");
      store = new FileStore();
      storeType = 'file';
    } else {
      throw e;
    }
  }

  app.use('/', function (req, res, next) {
    if (req.url === '/') {
      // Add store type to index.html
      res.setHeader('Content-Type', 'text/html');
      fs.readFile(path.join(__dirname, 'public', 'index.html'), function (err, data) {
        if (err) {
          throw err;
        }
        res.end(data.toString().replace('<html ', '<html class="' + storeType + '" '));
      });
    } else {
      next();
    }
  });

  app.use('/store', function (req, res) {
    switch (req.method) {
      case 'GET':
        store.get(req, res);
        break;
      case 'POST':
      case 'PUT':
        store.set(req, res);
        break;
    }
  });

  app.use(serveStatic('public'));
  app.use(function (req, res) {
    res.end('Hello World!\n');
  });

  http.createServer(app).listen(port, host, function () {
    console.log("Server listening to %s:%d", host, port);
  });
}());
