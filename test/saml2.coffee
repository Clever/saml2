_             = require 'underscore'
# util = require 'util'
saml2      = require '../lib/saml2'
assert = require 'assert'

describe 'saml2', ->

  describe 'xml metadata', ->
    xit 'is valid xml', (done) ->
      assert false
      done()
    xit 'contains expected fields', (done) ->
      assert false
      done()

  # Login
  describe 'login url', ->
    xit 'creates an AuthRequest that is base64 encoded and compressed', (done) ->
      assert false
      done()
    xit 'includes relay URL', (done) ->
      assert false
      done()
    xit 'is configured according to the identity provider', (done) ->
      assert false
      done()

  # Auth Request, before it is compressed and base-64 encoded
  describe 'AuthRequest', ->
    xit 'is valid xml', (done) ->
      assert false
      done()
    xit 'contains expected fields', (done) ->
      assert false
      done()

  # Assert
  describe 'assert', ->
    xit 'expects properly formatted XML', (done) ->
      assert false
      done()
    xit 'expects base64 encoded SAMLResponse', (done) ->
      assert false
      done()
    xit 'finds encrypted data in SAMLResponse', (done) ->
      assert false
      done()
    xit 'can decode encrypted data in SAMLResponse', (done) ->
      assert false
      done()
    xit 'fails to decode encrypted data with private key', (done) ->
      assert false
      done()
    xit 'returns claims and their values', (done) ->
      assert false
      done()
    xit 'errors if no claims are found', (done) ->
      assert false
      done()
    xit 'allows claims with single or multiple value(s)', (done) ->
      assert false
      done()
    xit 'does not verify the assertions session ID, by default', (done) ->
      assert false
      done()
    xit 'verifies the assertions session ID, if specified by user', (done) ->
      assert false
      done()
    xit 'verifies the documents signature', (done) ->
      assert false
      done()

  describe 'check_signature', ->
    xit 'verifies document is signed', (done) ->
      assert false
      done()

    # Other tests that *strictly* enforce the signature. For example...
    # - checks that correct part of document is signed
    # - checks that correct part of document is signed with correct signature

  describe 'IdentityProvider', ->
    xit 'validates configuration passed to constructor (urls, certificate)', (done) ->
      assert false
      done()

  describe 'ServiceProvider', ->
    # before each
    idp = new saml2.IdentityProvider 'login_url', 'logout_url', 'other_service_cert'

    it 'can be constructed', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      done()

    xit 'validates configuration given to constructor (private key, certificate)', (done) ->
      assert false
      done()

    it 'can create login url', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      sp.create_login_url(idp, done)

    _.each {'error1':'response1', 'error2':'response2'}, (response_text, error_type) ->
      xit "returns correct 'login_url' error for #{error_type} ", (done) ->
        assert false
        done()

    xit 'can assert', (done) ->
      assert false
      done()

    _.each {'error1':'response1', 'error2':'response2'}, (response_text, error_type) ->
      xit "returns correct 'assert' error for #{error_type} ", (done) ->
        assert false
        done()

