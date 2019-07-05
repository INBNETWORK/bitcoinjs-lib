'use strict';

var embed = require('./embed');

var p2ms = require('./p2ms');

var p2pk = require('./p2pk');

var p2pkh = require('./p2pkh');

var p2sh = require('./p2sh');

var p2wpkh = require('./p2wpkh');

var p2wsh = require('./p2wsh');

module.exports = {
  embed: embed,
  p2ms: p2ms,
  p2pk: p2pk,
  p2pkh: p2pkh,
  p2sh: p2sh,
  p2wpkh: p2wpkh,
  p2wsh: p2wsh, // TODO
  // witness commitment

};
