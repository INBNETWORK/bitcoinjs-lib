"use strict";

// {signature} {pubKey}
var bscript = require('../../script');

function isCompressedCanonicalPubKey(pubKey) {
  return bscript.isCanonicalPubKey(pubKey) && pubKey.length === 33;
}

function check(script) {
  var chunks = bscript.decompile(script);
  return chunks.length === 2 && bscript.isCanonicalScriptSignature(chunks[0]) && isCompressedCanonicalPubKey(chunks[1]);
}

check.toJSON = function () {
  return 'witnessPubKeyHash input';
};

module.exports = {
  check: check
};
