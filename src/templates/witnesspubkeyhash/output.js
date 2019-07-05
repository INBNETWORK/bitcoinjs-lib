"use strict";

// OP_0 {pubKeyHash}
var bscript = require('../../script');

var OPS = require('bitcoin-ops');

function check(script) {
  var buffer = bscript.compile(script);
  return buffer.length === 22 && buffer[0] === OPS.OP_0 && buffer[1] === 0x14;
}

check.toJSON = function () {
  return 'Witness pubKeyHash output';
};

module.exports = {
  check: check
};
