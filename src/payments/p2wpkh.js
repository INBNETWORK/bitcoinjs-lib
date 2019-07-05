"use strict";

var lazy = require('./lazy');

var typef = require('typeforce');

var OPS = require('bitcoin-ops');

var ecc = require('tiny-secp256k1');

var bcrypto = require('../crypto');

var bech32 = require('bech32');

var bscript = require('../script');

var BITCOIN_NETWORK = require('../networks').bitcoin;

var EMPTY_BUFFER = Buffer.alloc(0); // witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}

function p2wpkh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.pubkey && !a.witness) throw new TypeError('Not enough data');
  opts = Object.assign({
    validate: true
  }, opts || {});
  typef({
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    input: typef.maybe(typef.BufferN(0)),
    network: typef.maybe(typef.Object),
    output: typef.maybe(typef.BufferN(22)),
    pubkey: typef.maybe(ecc.isPoint),
    signature: typef.maybe(bscript.isCanonicalScriptSignature),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a);

  var _address = lazy.value(function () {
    var result = bech32.decode(a.address);
    var version = result.words.shift();
    var data = bech32.fromWords(result.words);
    return {
      version: version,
      prefix: result.prefix,
      data: Buffer.from(data)
    };
  });

  var network = a.network || BITCOIN_NETWORK;
  var o = {
    network: network
  };
  lazy.prop(o, 'address', function () {
    if (!o.hash) return;
    var words = bech32.toWords(o.hash);
    words.unshift(0x00);
    return bech32.encode(network.bech32, words);
  });
  lazy.prop(o, 'hash', function () {
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().data;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey || o.pubkey);
  });
  lazy.prop(o, 'output', function () {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_0, o.hash]);
  });
  lazy.prop(o, 'pubkey', function () {
    if (a.pubkey) return a.pubkey;
    if (!a.witness) return;
    return a.witness[1];
  });
  lazy.prop(o, 'signature', function () {
    if (!a.witness) return;
    return a.witness[0];
  });
  lazy.prop(o, 'input', function () {
    if (!o.witness) return;
    return EMPTY_BUFFER;
  });
  lazy.prop(o, 'witness', function () {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return [a.signature, a.pubkey];
  }); // extended validation

  if (opts.validate) {
    var hash;

    if (a.address) {
      if (network && network.bech32 !== _address().prefix) throw new TypeError('Invalid prefix or Network mismatch');
      if (_address().version !== 0x00) throw new TypeError('Invalid address version');
      if (_address().data.length !== 20) throw new TypeError('Invalid address data');
      hash = _address().data;
    }

    if (a.hash) {
      if (hash && !hash.equals(a.hash)) throw new TypeError('Hash mismatch');else hash = a.hash;
    }

    if (a.output) {
      if (a.output.length !== 22 || a.output[0] !== OPS.OP_0 || a.output[1] !== 0x14) throw new TypeError('Output is invalid');
      if (hash && !hash.equals(a.output.slice(2))) throw new TypeError('Hash mismatch');else hash = a.output.slice(2);
    }

    if (a.pubkey) {
      var pkh = bcrypto.hash160(a.pubkey);
      if (hash && !hash.equals(pkh)) throw new TypeError('Hash mismatch');else hash = pkh;
    }

    if (a.witness) {
      if (a.witness.length !== 2) throw new TypeError('Witness is invalid');
      if (!bscript.isCanonicalScriptSignature(a.witness[0])) throw new TypeError('Witness has invalid signature');
      if (!ecc.isPoint(a.witness[1])) throw new TypeError('Witness has invalid pubkey');
      if (a.signature && !a.signature.equals(a.witness[0])) throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(a.witness[1])) throw new TypeError('Pubkey mismatch');

      var _pkh = bcrypto.hash160(a.witness[1]);

      if (hash && !hash.equals(_pkh)) throw new TypeError('Hash mismatch');
    }
  }

  return Object.assign(o, a);
}

module.exports = p2wpkh;
