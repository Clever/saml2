var path = __dirname + '/' + (process.env.TEST_COV_SAML2 ? 'lib-js-cov' : 'lib-js') + '/saml2';
module.exports = require(path);
