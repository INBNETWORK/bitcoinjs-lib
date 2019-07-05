"use strict";

var decompile = require('./script').decompile;

var multisig = require('./templates/multisig');

var nullData = require('./templates/nulldata');

var pubKey = require('./templates/pubkey');

var pubKeyHash = require('./templates/pubkeyhash');

var scriptHash = require('./templates/scripthash');

var witnessPubKeyHash = require('./templates/witnesspubkeyhash');

var witnessScriptHash = require('./templates/witnessscripthash');

var witnessCommitment = require('./templates/witnesscommitment');

var types = {
  P2MS: 'multisig',
  NONSTANDARD: 'nonstandard',
  NULLDATA: 'nulldata',
  P2PK: 'pubkey',
  P2PKH: 'pubkeyhash',
  P2SH: 'scripthash',
  P2WPKH: 'witnesspubkeyhash',
  P2WSH: 'witnessscripthash',
  WITNESS_COMMITMENT: 'witnesscommitment'
};

function classifyOutput(script) {
  if (witnessPubKeyHash.output.check(script)) return types.P2WPKH;
  if (witnessScriptHash.output.check(script)) return types.P2WSH;
  if (pubKeyHash.output.check(script)) return types.P2PKH;
  if (scriptHash.output.check(script)) return types.P2SH; // XXX: optimization, below functions .decompile before use

  var chunks = decompile(script);
  if (!chunks) throw new TypeError('Invalid script');
  if (multisig.output.check(chunks)) return types.P2MS;
  if (pubKey.output.check(chunks)) return types.P2PK;
  if (witnessCommitment.output.check(chunks)) return types.WITNESS_COMMITMENT;
  if (nullData.output.check(chunks)) return types.NULLDATA;
  return types.NONSTANDARD;
}

function classifyInput(script, allowIncomplete) {
  // XXX: optimization, below functions .decompile before use
  var chunks = decompile(script);
  if (!chunks) throw new TypeError('Invalid script');
  if (pubKeyHash.input.check(chunks)) return types.P2PKH;
  if (scriptHash.input.check(chunks, allowIncomplete)) return types.P2SH;
  if (multisig.input.check(chunks, allowIncomplete)) return types.P2MS;
  if (pubKey.input.check(chunks)) return types.P2PK;
  return types.NONSTANDARD;
}

function classifyWitness(script, allowIncomplete) {
  // XXX: optimization, below functions .decompile before use
  var chunks = decompile(script);
  if (!chunks) throw new TypeError('Invalid script');
  if (witnessPubKeyHash.input.check(chunks)) return types.P2WPKH;
  if (witnessScriptHash.input.check(chunks, allowIncomplete)) return types.P2WSH;
  return types.NONSTANDARD;
}

module.exports = {
  input: classifyInput,
  output: classifyOutput,
  witness: classifyWitness,
  types: types
};
