"use strict";

// OP_RETURN {data}
var bscript = require('../script');

var OPS = require('bitcoin-ops');

function check(script) {
  var buffer = bscript.compile(script);
  return buffer.length > 1 && buffer[0] === OPS.OP_RETURN;
}

check.toJSON = function () {
  return 'null data output';
};

module.exports = {
  output: {
    check: check
  }
};
