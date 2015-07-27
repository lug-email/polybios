//jshint node: true
(function () {
  "use strict";
  var connect     = require('connect'),
      http        = require('http'),
      bodyParser  = require('body-parser'),
      serveStatic = require('serve-static'),
      fs          = require('fs'),
      path        = require('path'),
      app, port, host, store;

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

  store = new FileStore();

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
