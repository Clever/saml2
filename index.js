require('coffee-script');

if (process.env.TEST_COV_CLEVERJS) {
  module.exports = require('./lib-js-cov/clever');
} else {
  module.exports = require('./lib/clever');
}
