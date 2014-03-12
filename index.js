require('coffee-script');

if (process.env.TEST_COV_CLEVERJS) {
  module.exports = require('./lib-js-cov/saml2');
} else {
  module.exports = require('./lib/saml2');
}
