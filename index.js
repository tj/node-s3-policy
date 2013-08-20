
/**
 * Module dependencies.
 */

var crypto = require('crypto');

/**
 * Create an s3 policy and signature via `opts`:
 *
 *  - `acl` acl such as "public-read"
 *  - `expires` expiration date
 *  - `secret` s3 secret
 *  - `bucket` bucket name
 *  - `key` restrict key to prefix [""]
 *  - `type` restrict content-type prefix [""]
 *  - `length` max size restriction
 *
 * An object with `.signature` and `.policy` is returned.
 *
 * @param {Object} opts
 * @return {Object} 
 * @api public
 */

module.exports = function(opts){
  var ret = {};
  
  opts.conditions = [];

  opts.conditions.push(['starts-with', '$key', opts.key || '']);
  opts.conditions.push(['starts-with', '$Content-Type', opts.type || '']);
  opts.conditions.push(['starts-with', '$Content-Length', '']);

  if (opts.length) {
    opts.conditions.push(['content-length-range', 1, opts.length]);
  }

  ret.policy = policy(opts);
  ret.signature = signature(ret.policy, opts.secret);
  
  return ret;
};

/**
 * Create an s3 policy via `opts`.
 *
 * @param {Object} opts
 * @return {String}
 * @api public
 */

function policy(opts) {
  if (!opts) throw new Error('settings required');
  if (!opts.expires) throw new Error('.expires required');
  if (!opts.bucket) throw new Error('.bucket required');
  if (!opts.acl) throw new Error('.acl required');

  var conds = opts.conditions || [];
  conds.push({ bucket: opts.bucket });
  conds.push({ acl: opts.acl });
  
  var policy = {
    expiration: opts.expires.toISOString(),
    conditions: conds
  };

  var json = JSON.stringify(policy);
  var base = new Buffer(json).toString('base64');
  return base;
}

/**
 * SHA1 of the policy / secret.
 *
 * @param {String} policy
 * @param {String} secret
 * @return {String}
 * @api private
 */

function signature(policy, secret) {
  if (!secret) throw new Error('secret required');

  return crypto
    .createHmac('sha1', secret)
    .update(policy)
    .digest('base64');
}