/**
 * Compliance Wrapper (Middleman)
 */
const { sentinelOverride } = require('../governance');

module.exports = { 
  safetyHook: sentinelOverride 
};
