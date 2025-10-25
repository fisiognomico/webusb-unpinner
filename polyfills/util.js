// webpack-util-polyfill.js
// Minimal polyfill for Node.js 'util' module used by binary-xml

module.exports = {
  inspect: (obj) => JSON.stringify(obj),
  isArray: Array.isArray,
  isBoolean: (val) => typeof val === 'boolean',
  isNull: (val) => val === null,
  isNullOrUndefined: (val) => val == null,
  isNumber: (val) => typeof val === 'number',
  isString: (val) => typeof val === 'string',
  isSymbol: (val) => typeof val === 'symbol',
  isUndefined: (val) => val === undefined,
  isObject: (val) => val !== null && typeof val === 'object',
  isFunction: (val) => typeof val === 'function',
};
