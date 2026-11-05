// Test-only loopback resolution, including the Node TLS proxy used for client certs.
const dns = require('node:dns');
const original = dns.lookup.bind(dns);
dns.lookup = (hostname, options, callback) => {
  if (hostname !== 'privileged.localhost') return original(hostname, options, callback);
  if (typeof options === 'function') { callback = options; options = {}; }
  queueMicrotask(() => options?.all ? callback(null, [{address:'127.0.0.1',family:4}]) : callback(null,'127.0.0.1',4));
};
const originalPromise = dns.promises.lookup.bind(dns.promises);
dns.promises.lookup = async (hostname, options) => hostname === 'privileged.localhost'
  ? (options?.all ? [{address:'127.0.0.1',family:4}] : {address:'127.0.0.1',family:4}) : originalPromise(hostname,options);
