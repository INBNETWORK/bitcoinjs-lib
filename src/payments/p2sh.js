"use strict";

var lazy = require('./lazy');

var typef = require('typeforce');

var OPS = require('bitcoin-ops');

var bcrypto = require('../crypto');

var bscript = require('../script');

var BITCOIN_NETWORK = require('../networks').bitcoin;

var bs58check = require('bs58check');

function stacksEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every(function (x, i) {
    return x.equals(b[i]);
  });
} // input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL


function p2sh(a, opts) {
  if (!a.address && !a.hash && !a.output && !a.redeem && !a.input) throw new TypeError('Not enough data');
  opts = Object.assign({
    validate: true
  }, opts || {});
  typef({
    network: typef.maybe(typef.Object),
    address: typef.maybe(typef.String),
    hash: typef.maybe(typef.BufferN(20)),
    output: typef.maybe(typef.BufferN(23)),
    redeem: typef.maybe({
      network: typef.maybe(typef.Object),
      output: typef.maybe(typef.Buffer),
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer))
    }),
    input: typef.maybe(typef.Buffer),
    witness: typef.maybe(typef.arrayOf(typef.Buffer))
  }, a);
  var network = a.network;

  if (!network) {
    network = a.redeem && a.redeem.network || BITCOIN_NETWORK;
  }

  var o = {
    network: network
  };

  var _address = lazy.value(function () {
    var payload = bs58check.decode(a.address);
    var version = payload.readUInt8(0);
    var hash = payload.slice(1);
    return {
      version: version,
      hash: hash
    };
  });

  var _chunks = lazy.value(function () {
    return bscript.decompile(a.input);
  });

  var _redeem = lazy.value(function () {
    var chunks = _chunks();

    return {
      network: network,
      output: chunks[chunks.length - 1],
      input: bscript.compile(chunks.slice(0, -1)),
      witness: a.witness || []
    };
  }); // output dependents


  lazy.prop(o, 'address', function () {
    if (!o.hash) return;
    var payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(network.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', function () {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
  });
  lazy.prop(o, 'output', function () {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_HASH160, o.hash, OPS.OP_EQUAL]);
  }); // input dependents

  lazy.prop(o, 'redeem', function () {
    if (!a.input) return;
    return _redeem();
  });
  lazy.prop(o, 'input', function () {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile([].concat(bscript.decompile(a.redeem.input), a.redeem.output));
  });
  lazy.prop(o, 'witness', function () {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });

  if (opts.validate) {
    var hash;

    if (a.address) {
      if (_address().version !== network.scriptHash) throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }

    if (a.hash) {
      if (hash && !hash.equals(a.hash)) throw new TypeError('Hash mismatch');else hash = a.hash;
    }

    if (a.output) {
      if (a.output.length !== 23 || a.output[0] !== OPS.OP_HASH160 || a.output[1] !== 0x14 || a.output[22] !== OPS.OP_EQUAL) throw new TypeError('Output is invalid');
      var hash2 = a.output.slice(2, 22);
      if (hash && !hash.equals(hash2)) throw new TypeError('Hash mismatch');else hash = hash2;
    } // inlined to prevent 'no-inner-declarations' failing


    var checkRedeem = function checkRedeem(redeem) {
      // is the redeem output empty/invalid?
      if (redeem.output) {
        var decompile = bscript.decompile(redeem.output);
        if (!decompile || decompile.length < 1) throw new TypeError('Redeem.output too short'); // match hash against other sources

        var _hash = bcrypto.hash160(redeem.output);

        if (hash && !hash.equals(_hash)) throw new TypeError('Hash mismatch');else hash = _hash;
      }

      if (redeem.input) {
        var hasInput = redeem.input.length > 0;
        var hasWitness = redeem.witness && redeem.witness.length > 0;
        if (!hasInput && !hasWitness) throw new TypeError('Empty input');
        if (hasInput && hasWitness) throw new TypeError('Input and witness provided');

        if (hasInput) {
          var richunks = bscript.decompile(redeem.input);
          if (!bscript.isPushOnly(richunks)) throw new TypeError('Non push-only scriptSig');
        }
      }
    };

    if (a.input) {
      var chunks = _chunks();

      if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
      if (!Buffer.isBuffer(_redeem().output)) throw new TypeError('Input is invalid');
      checkRedeem(_redeem());
    }

    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network) throw new TypeError('Network mismatch');

      if (a.input) {
        var redeem = _redeem();

        if (a.redeem.output && !a.redeem.output.equals(redeem.output)) throw new TypeError('Redeem.output mismatch');
        if (a.redeem.input && !a.redeem.input.equals(redeem.input)) throw new TypeError('Redeem.input mismatch');
      }

      checkRedeem(a.redeem);
    }

    if (a.witness) {
      if (a.redeem && a.redeem.witness && !stacksEqual(a.redeem.witness, a.witness)) throw new TypeError('Witness and redeem.witness mismatch');
    }
  }

  return Object.assign(o, a);
}

module.exports = p2sh;
