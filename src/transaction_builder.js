"use strict";

function _instanceof(left, right) { if (right != null && typeof Symbol !== "undefined" && right[Symbol.hasInstance]) { return right[Symbol.hasInstance](left); } else { return left instanceof right; } }

var Buffer = require('safe-buffer').Buffer;

var baddress = require('./address');

var bcrypto = require('./crypto');

var bscript = require('./script');

var networks = require('./networks');

var ops = require('bitcoin-ops');

var payments = require('./payments');

var typeforce = require('typeforce');

var types = require('./types');

var classify = require('./classify');

var SCRIPT_TYPES = classify.types;

var ECPair = require('./ecpair');

var Transaction = require('./transaction');

function expandInput(scriptSig, witnessStack, type, scriptPubKey) {
  if (scriptSig.length === 0 && witnessStack.length === 0) return {};

  if (!type) {
    var ssType = classify.input(scriptSig, true);
    var wsType = classify.witness(witnessStack, true);
    if (ssType === SCRIPT_TYPES.NONSTANDARD) ssType = undefined;
    if (wsType === SCRIPT_TYPES.NONSTANDARD) wsType = undefined;
    type = ssType || wsType;
  }

  switch (type) {
    case SCRIPT_TYPES.P2WPKH:
    {
      var _payments$p2wpkh = payments.p2wpkh({
          witness: witnessStack
        }),
        output = _payments$p2wpkh.output,
        pubkey = _payments$p2wpkh.pubkey,
        signature = _payments$p2wpkh.signature;

      return {
        prevOutScript: output,
        prevOutType: SCRIPT_TYPES.P2WPKH,
        pubkeys: [pubkey],
        signatures: [signature]
      };
    }

    case SCRIPT_TYPES.P2PKH:
    {
      var _payments$p2pkh = payments.p2pkh({
          input: scriptSig
        }),
        _output = _payments$p2pkh.output,
        _pubkey = _payments$p2pkh.pubkey,
        _signature = _payments$p2pkh.signature;

      return {
        prevOutScript: _output,
        prevOutType: SCRIPT_TYPES.P2PKH,
        pubkeys: [_pubkey],
        signatures: [_signature]
      };
    }

    case SCRIPT_TYPES.P2PK:
    {
      var _payments$p2pk = payments.p2pk({
          input: scriptSig
        }),
        _signature2 = _payments$p2pk.signature;

      return {
        prevOutType: SCRIPT_TYPES.P2PK,
        pubkeys: [undefined],
        signatures: [_signature2]
      };
    }

    case SCRIPT_TYPES.P2MS:
    {
      var _payments$p2ms = payments.p2ms({
          input: scriptSig,
          output: scriptPubKey
        }, {
          allowIncomplete: true
        }),
        m = _payments$p2ms.m,
        pubkeys = _payments$p2ms.pubkeys,
        signatures = _payments$p2ms.signatures;

      return {
        prevOutType: SCRIPT_TYPES.P2MS,
        pubkeys: pubkeys,
        signatures: signatures,
        maxSignatures: m
      };
    }
  }

  if (type === SCRIPT_TYPES.P2SH) {
    var _payments$p2sh = payments.p2sh({
        input: scriptSig,
        witness: witnessStack
      }),
      _output2 = _payments$p2sh.output,
      redeem = _payments$p2sh.redeem;

    var outputType = classify.output(redeem.output);
    var expanded = expandInput(redeem.input, redeem.witness, outputType, redeem.output);
    if (!expanded.prevOutType) return {};
    return {
      prevOutScript: _output2,
      prevOutType: SCRIPT_TYPES.P2SH,
      redeemScript: redeem.output,
      redeemScriptType: expanded.prevOutType,
      witnessScript: expanded.witnessScript,
      witnessScriptType: expanded.witnessScriptType,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures
    };
  }

  if (type === SCRIPT_TYPES.P2WSH) {
    var _payments$p2wsh = payments.p2wsh({
        input: scriptSig,
        witness: witnessStack
      }),
      _output3 = _payments$p2wsh.output,
      _redeem = _payments$p2wsh.redeem;

    var _outputType = classify.output(_redeem.output);

    var _expanded;

    if (_outputType === SCRIPT_TYPES.P2WPKH) {
      _expanded = expandInput(_redeem.input, _redeem.witness, _outputType);
    } else {
      _expanded = expandInput(bscript.compile(_redeem.witness), [], _outputType, _redeem.output);
    }

    if (!_expanded.prevOutType) return {};
    return {
      prevOutScript: _output3,
      prevOutType: SCRIPT_TYPES.P2WSH,
      witnessScript: _redeem.output,
      witnessScriptType: _expanded.prevOutType,
      pubkeys: _expanded.pubkeys,
      signatures: _expanded.signatures
    };
  }

  return {
    prevOutType: SCRIPT_TYPES.NONSTANDARD,
    prevOutScript: scriptSig
  };
} // could be done in expandInput, but requires the original Transaction for hashForSignature


function fixMultisigOrder(input, transaction, vin) {
  if (input.redeemScriptType !== SCRIPT_TYPES.P2MS || !input.redeemScript) return;
  if (input.pubkeys.length === input.signatures.length) return;
  var unmatched = input.signatures.concat();
  input.signatures = input.pubkeys.map(function (pubKey) {
    var keyPair = ECPair.fromPublicKey(pubKey);
    var match; // check for a signature

    unmatched.some(function (signature, i) {
      // skip if undefined || OP_0
      if (!signature) return false; // TODO: avoid O(n) hashForSignature

      var parsed = bscript.signature.decode(signature);
      var hash = transaction.hashForSignature(vin, input.redeemScript, parsed.hashType); // skip if signature does not match pubKey

      if (!keyPair.verify(hash, parsed.signature)) return false; // remove matched signature from unmatched

      unmatched[i] = undefined;
      match = signature;
      return true;
    });
    return match;
  });
}

function expandOutput(script, ourPubKey) {
  typeforce(types.Buffer, script);
  var type = classify.output(script);

  switch (type) {
    case SCRIPT_TYPES.P2PKH:
    {
      if (!ourPubKey) return {
        type: type // does our hash160(pubKey) match the output scripts?

      };
      var pkh1 = payments.p2pkh({
        output: script
      }).hash;
      var pkh2 = bcrypto.hash160(ourPubKey);
      if (!pkh1.equals(pkh2)) return {
        type: type
      };
      return {
        type: type,
        pubkeys: [ourPubKey],
        signatures: [undefined]
      };
    }

    case SCRIPT_TYPES.P2WPKH:
    {
      if (!ourPubKey) return {
        type: type // does our hash160(pubKey) match the output scripts?

      };
      var wpkh1 = payments.p2wpkh({
        output: script
      }).hash;
      var wpkh2 = bcrypto.hash160(ourPubKey);
      if (!wpkh1.equals(wpkh2)) return {
        type: type
      };
      return {
        type: type,
        pubkeys: [ourPubKey],
        signatures: [undefined]
      };
    }

    case SCRIPT_TYPES.P2PK:
    {
      var p2pk = payments.p2pk({
        output: script
      });
      return {
        type: type,
        pubkeys: [p2pk.pubkey],
        signatures: [undefined]
      };
    }

    case SCRIPT_TYPES.P2MS:
    {
      var p2ms = payments.p2ms({
        output: script
      });
      return {
        type: type,
        pubkeys: p2ms.pubkeys,
        signatures: p2ms.pubkeys.map(function () {
          return undefined;
        }),
        maxSignatures: p2ms.m
      };
    }
  }

  return {
    type: type
  };
}

function prepareInput(input, ourPubKey, redeemScript, witnessScript) {
  if (redeemScript && witnessScript) {
    var p2wsh = payments.p2wsh({
      redeem: {
        output: witnessScript
      }
    });
    var p2wshAlt = payments.p2wsh({
      output: redeemScript
    });
    var p2sh = payments.p2sh({
      redeem: {
        output: redeemScript
      }
    });
    var p2shAlt = payments.p2sh({
      redeem: p2wsh
    }); // enforces P2SH(P2WSH(...))

    if (!p2wsh.hash.equals(p2wshAlt.hash)) throw new Error('Witness script inconsistent with prevOutScript');
    if (!p2sh.hash.equals(p2shAlt.hash)) throw new Error('Redeem script inconsistent with prevOutScript');
    var expanded = expandOutput(p2wsh.redeem.output, ourPubKey);
    if (!expanded.pubkeys) throw new Error(expanded.type + ' not supported as witnessScript (' + bscript.toASM(witnessScript) + ')');

    if (input.signatures && input.signatures.some(function (x) {
      return x;
    })) {
      expanded.signatures = input.signatures;
    }

    var signScript = witnessScript;
    if (expanded.type === SCRIPT_TYPES.P2WPKH) throw new Error('P2SH(P2WSH(P2WPKH)) is a consensus failure');
    return {
      redeemScript: redeemScript,
      redeemScriptType: SCRIPT_TYPES.P2WSH,
      witnessScript: witnessScript,
      witnessScriptType: expanded.type,
      prevOutType: SCRIPT_TYPES.P2SH,
      prevOutScript: p2sh.output,
      hasWitness: true,
      signScript: signScript,
      signType: expanded.type,
      pubkeys: expanded.pubkeys,
      signatures: expanded.signatures,
      maxSignatures: expanded.maxSignatures
    };
  }

  if (redeemScript) {
    var _p2sh = payments.p2sh({
      redeem: {
        output: redeemScript
      }
    });

    if (input.prevOutScript) {
      var _p2shAlt;

      try {
        _p2shAlt = payments.p2sh({
          output: input.prevOutScript
        });
      } catch (e) {
        throw new Error('PrevOutScript must be P2SH');
      }

      if (!_p2sh.hash.equals(_p2shAlt.hash)) throw new Error('Redeem script inconsistent with prevOutScript');
    }

    var _expanded2 = expandOutput(_p2sh.redeem.output, ourPubKey);

    if (!_expanded2.pubkeys) throw new Error(_expanded2.type + ' not supported as redeemScript (' + bscript.toASM(redeemScript) + ')');

    if (input.signatures && input.signatures.some(function (x) {
      return x;
    })) {
      _expanded2.signatures = input.signatures;
    }

    var _signScript = redeemScript;

    if (_expanded2.type === SCRIPT_TYPES.P2WPKH) {
      _signScript = payments.p2pkh({
        pubkey: _expanded2.pubkeys[0]
      }).output;
    }

    return {
      redeemScript: redeemScript,
      redeemScriptType: _expanded2.type,
      prevOutType: SCRIPT_TYPES.P2SH,
      prevOutScript: _p2sh.output,
      hasWitness: _expanded2.type === SCRIPT_TYPES.P2WPKH,
      signScript: _signScript,
      signType: _expanded2.type,
      pubkeys: _expanded2.pubkeys,
      signatures: _expanded2.signatures,
      maxSignatures: _expanded2.maxSignatures
    };
  }

  if (witnessScript) {
    var _p2wsh = payments.p2wsh({
      redeem: {
        output: witnessScript
      }
    });

    if (input.prevOutScript) {
      var _p2wshAlt = payments.p2wsh({
        output: input.prevOutScript
      });

      if (!_p2wsh.hash.equals(_p2wshAlt.hash)) throw new Error('Witness script inconsistent with prevOutScript');
    }

    var _expanded3 = expandOutput(_p2wsh.redeem.output, ourPubKey);

    if (!_expanded3.pubkeys) throw new Error(_expanded3.type + ' not supported as witnessScript (' + bscript.toASM(witnessScript) + ')');

    if (input.signatures && input.signatures.some(function (x) {
      return x;
    })) {
      _expanded3.signatures = input.signatures;
    }

    var _signScript2 = witnessScript;
    if (_expanded3.type === SCRIPT_TYPES.P2WPKH) throw new Error('P2WSH(P2WPKH) is a consensus failure');
    return {
      witnessScript: witnessScript,
      witnessScriptType: _expanded3.type,
      prevOutType: SCRIPT_TYPES.P2WSH,
      prevOutScript: _p2wsh.output,
      hasWitness: true,
      signScript: _signScript2,
      signType: _expanded3.type,
      pubkeys: _expanded3.pubkeys,
      signatures: _expanded3.signatures,
      maxSignatures: _expanded3.maxSignatures
    };
  }

  if (input.prevOutType && input.prevOutScript) {
    // embedded scripts are not possible without extra information
    if (input.prevOutType === SCRIPT_TYPES.P2SH) throw new Error('PrevOutScript is ' + input.prevOutType + ', requires redeemScript');
    if (input.prevOutType === SCRIPT_TYPES.P2WSH) throw new Error('PrevOutScript is ' + input.prevOutType + ', requires witnessScript');
    if (!input.prevOutScript) throw new Error('PrevOutScript is missing');

    var _expanded4 = expandOutput(input.prevOutScript, ourPubKey);

    if (!_expanded4.pubkeys) throw new Error(_expanded4.type + ' not supported (' + bscript.toASM(input.prevOutScript) + ')');

    if (input.signatures && input.signatures.some(function (x) {
      return x;
    })) {
      _expanded4.signatures = input.signatures;
    }

    var _signScript3 = input.prevOutScript;

    if (_expanded4.type === SCRIPT_TYPES.P2WPKH) {
      _signScript3 = payments.p2pkh({
        pubkey: _expanded4.pubkeys[0]
      }).output;
    }

    return {
      prevOutType: _expanded4.type,
      prevOutScript: input.prevOutScript,
      hasWitness: _expanded4.type === SCRIPT_TYPES.P2WPKH,
      signScript: _signScript3,
      signType: _expanded4.type,
      pubkeys: _expanded4.pubkeys,
      signatures: _expanded4.signatures,
      maxSignatures: _expanded4.maxSignatures
    };
  }

  var prevOutScript = payments.p2pkh({
    pubkey: ourPubKey
  }).output;
  return {
    prevOutType: SCRIPT_TYPES.P2PKH,
    prevOutScript: prevOutScript,
    hasWitness: false,
    signScript: prevOutScript,
    signType: SCRIPT_TYPES.P2PKH,
    pubkeys: [ourPubKey],
    signatures: [undefined]
  };
}

function build(type, input, allowIncomplete) {
  var pubkeys = input.pubkeys || [];
  var signatures = input.signatures || [];

  switch (type) {
    case SCRIPT_TYPES.P2PKH:
    {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pkh({
        pubkey: pubkeys[0],
        signature: signatures[0]
      });
    }

    case SCRIPT_TYPES.P2WPKH:
    {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2wpkh({
        pubkey: pubkeys[0],
        signature: signatures[0]
      });
    }

    case SCRIPT_TYPES.P2PK:
    {
      if (pubkeys.length === 0) break;
      if (signatures.length === 0) break;
      return payments.p2pk({
        signature: signatures[0]
      });
    }

    case SCRIPT_TYPES.P2MS:
    {
      var m = input.maxSignatures;

      if (allowIncomplete) {
        signatures = signatures.map(function (x) {
          return x || ops.OP_0;
        });
      } else {
        signatures = signatures.filter(function (x) {
          return x;
        });
      } // if the transaction is not not complete (complete), or if signatures.length === m, validate
      // otherwise, the number of OP_0's may be >= m, so don't validate (boo)


      var validate = !allowIncomplete || m === signatures.length;
      return payments.p2ms({
        m: m,
        pubkeys: pubkeys,
        signatures: signatures
      }, {
        allowIncomplete: allowIncomplete,
        validate: validate
      });
    }

    case SCRIPT_TYPES.P2SH:
    {
      var redeem = build(input.redeemScriptType, input, allowIncomplete);
      if (!redeem) return;
      return payments.p2sh({
        redeem: {
          output: redeem.output || input.redeemScript,
          input: redeem.input,
          witness: redeem.witness
        }
      });
    }

    case SCRIPT_TYPES.P2WSH:
    {
      var _redeem2 = build(input.witnessScriptType, input, allowIncomplete);

      if (!_redeem2) return;
      return payments.p2wsh({
        redeem: {
          output: input.witnessScript,
          input: _redeem2.input,
          witness: _redeem2.witness
        }
      });
    }
  }
}

function TransactionBuilder(network, maximumFeeRate) {
  this.__prevTxSet = {};
  this.network = network || networks.bitcoin; // WARNING: This is __NOT__ to be relied on, its just another potential safety mechanism (safety in-depth)

  this.maximumFeeRate = maximumFeeRate || 2500;
  this.__inputs = [];
  this.__tx = new Transaction();
  this.__tx.version = 2;
}

TransactionBuilder.prototype.setLockTime = function (locktime) {
  typeforce(types.UInt32, locktime); // if any signatures exist, throw

  if (this.__inputs.some(function (input) {
    if (!input.signatures) return false;
    return input.signatures.some(function (s) {
      return s;
    });
  })) {
    throw new Error('No, this would invalidate signatures');
  }

  this.__tx.locktime = locktime;
};

TransactionBuilder.prototype.setVersion = function (version) {
  typeforce(types.UInt32, version); // XXX: this might eventually become more complex depending on what the versions represent

  this.__tx.version = version;
};

TransactionBuilder.fromTransaction = function (transaction, network) {
  var txb = new TransactionBuilder(network); // Copy transaction fields

  txb.setVersion(transaction.version);
  txb.setLockTime(transaction.locktime); // Copy outputs (done first to avoid signature invalidation)

  transaction.outs.forEach(function (txOut) {
    txb.addOutput(txOut.script, txOut.value);
  }); // Copy inputs

  transaction.ins.forEach(function (txIn) {
    txb.__addInputUnsafe(txIn.hash, txIn.index, {
      sequence: txIn.sequence,
      script: txIn.script,
      witness: txIn.witness
    });
  }); // fix some things not possible through the public API

  txb.__inputs.forEach(function (input, i) {
    fixMultisigOrder(input, transaction, i);
  });

  return txb;
};

TransactionBuilder.prototype.addInput = function (txHash, vout, sequence, prevOutScript) {
  if (!this.__canModifyInputs()) {
    throw new Error('No, this would invalidate signatures');
  }

  var value; // is it a hex string?

  if (typeof txHash === 'string') {
    // transaction hashs's are displayed in reverse order, un-reverse it
    txHash = Buffer.from(txHash, 'hex').reverse(); // is it a Transaction object?
  } else if (_instanceof(txHash, Transaction)) {
    var txOut = txHash.outs[vout];
    prevOutScript = txOut.script;
    value = txOut.value;
    txHash = txHash.getHash();
  }

  return this.__addInputUnsafe(txHash, vout, {
    sequence: sequence,
    prevOutScript: prevOutScript,
    value: value
  });
};

TransactionBuilder.prototype.__addInputUnsafe = function (txHash, vout, options) {
  if (Transaction.isCoinbaseHash(txHash)) {
    throw new Error('coinbase inputs not supported');
  }

  var prevTxOut = txHash.toString('hex') + ':' + vout;
  if (this.__prevTxSet[prevTxOut] !== undefined) throw new Error('Duplicate TxOut: ' + prevTxOut);
  var input = {}; // derive what we can from the scriptSig

  if (options.script !== undefined) {
    input = expandInput(options.script, options.witness || []);
  } // if an input value was given, retain it


  if (options.value !== undefined) {
    input.value = options.value;
  } // derive what we can from the previous transactions output script


  if (!input.prevOutScript && options.prevOutScript) {
    var prevOutType;

    if (!input.pubkeys && !input.signatures) {
      var expanded = expandOutput(options.prevOutScript);

      if (expanded.pubkeys) {
        input.pubkeys = expanded.pubkeys;
        input.signatures = expanded.signatures;
      }

      prevOutType = expanded.type;
    }

    input.prevOutScript = options.prevOutScript;
    input.prevOutType = prevOutType || classify.output(options.prevOutScript);
  }

  var vin = this.__tx.addInput(txHash, vout, options.sequence, options.scriptSig);

  this.__inputs[vin] = input;
  this.__prevTxSet[prevTxOut] = true;
  return vin;
};

TransactionBuilder.prototype.addOutput = function (scriptPubKey, value) {
  if (!this.__canModifyOutputs()) {
    throw new Error('No, this would invalidate signatures');
  } // Attempt to get a script if it's a base58 or bech32 address string


  if (typeof scriptPubKey === 'string') {
    scriptPubKey = baddress.toOutputScript(scriptPubKey, this.network);
  }

  return this.__tx.addOutput(scriptPubKey, value);
};

TransactionBuilder.prototype.build = function () {
  return this.__build(false);
};

TransactionBuilder.prototype.buildIncomplete = function () {
  return this.__build(true);
};

TransactionBuilder.prototype.__build = function (allowIncomplete) {
  if (!allowIncomplete) {
    if (!this.__tx.ins.length) throw new Error('Transaction has no inputs');
    if (!this.__tx.outs.length) throw new Error('Transaction has no outputs');
  }

  var tx = this.__tx.clone(); // create script signatures from inputs


  this.__inputs.forEach(function (input, i) {
    if (!input.prevOutType && !allowIncomplete) throw new Error('Transaction is not complete');
    var result = build(input.prevOutType, input, allowIncomplete);

    if (!result) {
      if (!allowIncomplete && input.prevOutType === SCRIPT_TYPES.NONSTANDARD) throw new Error('Unknown input type');
      if (!allowIncomplete) throw new Error('Not enough information');
      return;
    }

    tx.setInputScript(i, result.input);
    tx.setWitness(i, result.witness);
  });

  if (!allowIncomplete) {
    // do not rely on this, its merely a last resort
    if (this.__overMaximumFees(tx.virtualSize())) {
      throw new Error('Transaction has absurd fees');
    }
  }

  return tx;
};

function canSign(input) {
  return input.signScript !== undefined && input.signType !== undefined && input.pubkeys !== undefined && input.signatures !== undefined && input.signatures.length === input.pubkeys.length && input.pubkeys.length > 0 && (input.hasWitness === false || input.value !== undefined);
}

TransactionBuilder.prototype.sign = function (vin, keyPair, redeemScript, hashType, witnessValue, witnessScript) {
  // TODO: remove keyPair.network matching in 4.0.0
  if (keyPair.network && keyPair.network !== this.network) throw new TypeError('Inconsistent network');
  if (!this.__inputs[vin]) throw new Error('No input at index: ' + vin);
  hashType = hashType || Transaction.SIGHASH_ALL;
  if (this.__needsOutputs(hashType)) throw new Error('Transaction needs outputs');
  var input = this.__inputs[vin]; // if redeemScript was previously provided, enforce consistency

  if (input.redeemScript !== undefined && redeemScript && !input.redeemScript.equals(redeemScript)) {
    throw new Error('Inconsistent redeemScript');
  }

  var ourPubKey = keyPair.publicKey || keyPair.getPublicKey();

  if (!canSign(input)) {
    if (witnessValue !== undefined) {
      if (input.value !== undefined && input.value !== witnessValue) throw new Error('Input didn\'t match witnessValue');
      typeforce(types.Satoshi, witnessValue);
      input.value = witnessValue;
    }

    if (!canSign(input)) {
      var prepared = prepareInput(input, ourPubKey, redeemScript, witnessScript); // updates inline

      Object.assign(input, prepared);
    }

    if (!canSign(input)) throw Error(input.prevOutType + ' not supported');
  } // ready to sign


  var signatureHash;

  if (input.hasWitness) {
    signatureHash = this.__tx.hashForWitnessV0(vin, input.signScript, input.value, hashType);
  } else {
    signatureHash = this.__tx.hashForSignature(vin, input.signScript, hashType);
  } // enforce in order signing of public keys


  var signed = input.pubkeys.some(function (pubKey, i) {
    if (!ourPubKey.equals(pubKey)) return false;
    if (input.signatures[i]) throw new Error('Signature already exists'); // TODO: add tests

    if (ourPubKey.length !== 33 && input.hasWitness) {
      throw new Error('BIP143 rejects uncompressed public keys in P2WPKH or P2WSH');
    }

    var signature = keyPair.sign(signatureHash);
    input.signatures[i] = bscript.signature.encode(signature, hashType);
    return true;
  });
  if (!signed) throw new Error('Key pair cannot sign for this input');
};

function signatureHashType(buffer) {
  return buffer.readUInt8(buffer.length - 1);
}

TransactionBuilder.prototype.__canModifyInputs = function () {
  return this.__inputs.every(function (input) {
    if (!input.signatures) return true;
    return input.signatures.every(function (signature) {
      if (!signature) return true;
      var hashType = signatureHashType(signature); // if SIGHASH_ANYONECANPAY is set, signatures would not
      // be invalidated by more inputs

      return hashType & Transaction.SIGHASH_ANYONECANPAY;
    });
  });
};

TransactionBuilder.prototype.__needsOutputs = function (signingHashType) {
  if (signingHashType === Transaction.SIGHASH_ALL) {
    return this.__tx.outs.length === 0;
  } // if inputs are being signed with SIGHASH_NONE, we don't strictly need outputs
  // .build() will fail, but .buildIncomplete() is OK


  return this.__tx.outs.length === 0 && this.__inputs.some(function (input) {
    if (!input.signatures) return false;
    return input.signatures.some(function (signature) {
      if (!signature) return false; // no signature, no issue

      var hashType = signatureHashType(signature);
      if (hashType & Transaction.SIGHASH_NONE) return false; // SIGHASH_NONE doesn't care about outputs

      return true; // SIGHASH_* does care
    });
  });
};

TransactionBuilder.prototype.__canModifyOutputs = function () {
  var nInputs = this.__tx.ins.length;
  var nOutputs = this.__tx.outs.length;
  return this.__inputs.every(function (input) {
    if (input.signatures === undefined) return true;
    return input.signatures.every(function (signature) {
      if (!signature) return true;
      var hashType = signatureHashType(signature);
      var hashTypeMod = hashType & 0x1f;
      if (hashTypeMod === Transaction.SIGHASH_NONE) return true;

      if (hashTypeMod === Transaction.SIGHASH_SINGLE) {
        // if SIGHASH_SINGLE is set, and nInputs > nOutputs
        // some signatures would be invalidated by the addition
        // of more outputs
        return nInputs <= nOutputs;
      }
    });
  });
};

TransactionBuilder.prototype.__overMaximumFees = function (bytes) {
  // not all inputs will have .value defined
  var incoming = this.__inputs.reduce(function (a, x) {
    return a + (x.value >>> 0);
  }, 0); // but all outputs do, and if we have any input value
  // we can immediately determine if the outputs are too small


  var outgoing = this.__tx.outs.reduce(function (a, x) {
    return a + x.value;
  }, 0);

  var fee = incoming - outgoing;
  var feeRate = fee / bytes;
  return feeRate > this.maximumFeeRate;
};

module.exports = TransactionBuilder;
