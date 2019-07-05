"use strict";

// OP_0 {scriptHash}
var bscript = require('../../script');

var OPS = require('bitcoin-ops');

function check(script) {
  var buffer = bscript.compile(script);
  return buffer.length === 34 && buffer[0] === OPS.OP_0 && buffer[1] === 0x20;
}

check.toJSON = function () {
  return 'Witness scriptHash output';
};

module.exports = {
  check: check
};
