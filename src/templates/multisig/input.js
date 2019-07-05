"use strict";

// OP_0 [signatures ...]
var bscript = require('../../script');

var OPS = require('bitcoin-ops');

function partialSignature(value) {
  return value === OPS.OP_0 || bscript.isCanonicalScriptSignature(value);
}

function check(script, allowIncomplete) {
  var chunks = bscript.decompile(script);
  if (chunks.length < 2) return false;
  if (chunks[0] !== OPS.OP_0) return false;

  if (allowIncomplete) {
    return chunks.slice(1).every(partialSignature);
  }

  return chunks.slice(1).every(bscript.isCanonicalScriptSignature);
}

check.toJSON = function () {
  return 'multisig input';
};

module.exports = {
  check: check
};
