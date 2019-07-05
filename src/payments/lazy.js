"use strict";

function prop(object, name, f) {
  Object.defineProperty(object, name, {
    configurable: true,
    enumerable: true,
    get: function get() {
      var value = f.call(this);
      this[name] = value;
      return value;
    },
    set: function set(value) {
      Object.defineProperty(this, name, {
        configurable: true,
        enumerable: true,
        value: value,
        writable: true
      });
    }
  });
}

function value(f) {
  var value;
  return function () {
    if (value !== undefined) return value;
    value = f();
    return value;
  };
}

module.exports = {
  prop: prop,
  value: value
};
