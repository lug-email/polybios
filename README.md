# polybios

Just a ugly frontend for OpenPGP.js

## Polybius

Πολύβιος was an Ancient Greek historian and scholar who invented one of the first tool used to encrypt and decrypt messages, the [Polybius Square](http://en.wikipedia.org/wiki/Polybius_square).

## Installation

    npm install polybios
    mv node_modules/polybios/node_modules/* node_modules/ && rm -rf  node_modules/polybios/node_modules/ && mv node_modules/polybios/* . && rm -rf node_modules/polybios
    npm start

Then point your browser to `http://127.0.0.1:9253/`.

For now, your keyring is saved in a `store` plaintext file at the root of the application folder. Be sure to protetc this file.

## Credits

### Icon

Lock Icon by [GraphicLoads](http://graphicloads.com) is freeware.
Source: [IconArchive](http://www.iconarchive.com/show/colorful-long-shadow-icons-by-graphicloads/Lock-icon.html)

### Layout

I for now use the [Pure CSS framework](http://purecss.io/), which is free to use under the Yahoo! Inc. BSD license.
See the [LICENSE file](https://github.com/yahoo/pure-site/blob/master/LICENSE.md) for its license text and copyright information.
