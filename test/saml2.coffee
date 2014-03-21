_             = require 'underscore'
assert        = require 'assert'
async         = require 'async'
fs            = require 'fs'
saml2         = require "#{__dirname}/../index"
url           = require 'url'
util          = require 'util'
xmldom        = require 'xmldom'

describe 'saml2', ->

  dom_from_data_file = (filename) ->
    (new xmldom.DOMParser()).parseFromString fs.readFileSync("#{__dirname}/data/#{filename}").toString()

  before ->
    @good_response_dom = dom_from_data_file "good_response.xml"

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
    it 'contains expected fields', (done) ->
      saml2.create_authn_request 'https://sp.example.com/metadata.xml', 'https://sp.example.com/assert', 'https://idp.example.com/login', (err, result) ->
        assert not err?, "Got error: #{err}"
        dom = (new xmldom.DOMParser()).parseFromString result
        authn_request = dom.getElementsByTagName('AuthnRequest')[0]

        required_attributes =
          Version: '2.0'
          Destination: 'https://idp.example.com/login'
          AssertionConsumerServiceURL: 'https://sp.example.com/assert'
          ProtocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

        _(required_attributes).each (req_value, req_name) ->
          assert _(authn_request.attributes).some((attr) -> attr.name is req_name and attr.value is req_value)
          , "Expected to find attribute '#{req_name}' with value '#{req_value}'!"

        assert _(authn_request.attributes).some((attr) -> attr.name is "ID"), "Missing required attribute 'ID'"
        assert.equal dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')[0].firstChild.data, 'https://sp.example.com/metadata.xml'
        done()

  describe 'check_status_success', ->
    it 'accepts a valid success status', (done) ->
      saml2.check_status_success @good_response_dom, (err) ->
        assert not err?, "Got error: #{err}"
        done()

    it 'rejects a missing success status', (done) ->
      saml2.check_status_success dom_from_data_file("response_error_status.xml"), (err) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

    it 'rejects a missing status', (done) ->
      saml2.check_status_success dom_from_data_file("response_no_status.xml"), (err) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

  describe 'pretty_assertion_attributes', ->
    it 'creates a correct user object', ->
      test_attributes =
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [ "tuser@example.com" ]
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": [ "Test User" ]
        "http://schemas.xmlsoap.org/claims/Group": [ "Test Group" ]

      expected =
        email: "tuser@example.com"
        name: "Test User"
        group: "Test Group"

      assert.deepEqual saml2.pretty_assertion_attributes(test_attributes), expected

  describe 'decrypt_assertion', ->
    it 'decrypts and extracts an assertion', (done) ->
      key = fs.readFileSync("#{__dirname}/data/test.pem").toString()
      saml2.decrypt_assertion @good_response_dom, key, (err, result) ->
        assert not err?, "Got error: #{err}"
        assert.equal result, fs.readFileSync("#{__dirname}/data/good_response_decrypted.xml").toString()
        done()

    it 'errors if an incorrect key is used', (done) ->
      key = fs.readFileSync("#{__dirname}/data/test2.pem").toString()
      saml2.decrypt_assertion @good_response_dom, key, (err, result) ->
        assert (err instanceof Error), "Did not get expected error."
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
    it 'can be constructed', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      done()

    xit 'validates configuration given to constructor (private key, certificate)', (done) ->
      assert false
      done()

    it 'can create login url', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      idp = new saml2.IdentityProvider 'http://idp.example.com/login', 'http://idp.example.com/logout', 'other_service_cert'

      async.waterfall [
        (cb_wf) => sp.create_login_url idp, 'http://sp.example.com/assert', cb_wf
      ], (err, login_url, id) ->
        assert not err?, "Error creating login URL: #{err}"
        parsed_url = url.parse login_url, true
        saml_request = parsed_url.query?.SAMLRequest?
        assert saml_request, 'Could not find SAMLRequest in url query parameters'
        done()

    login_url_errors =
      'assert URL not given':'response1'
      'not HTTPS':'response2'

    _.each login_url_errors, (response_text, error_type) ->
      xit "returns correct 'login_url' error for #{error_type} ", (done) ->
        sp = new saml2.ServiceProvider 'private_key', 'cert'
        idp = new saml2.IdentityProvider 'login_url', 'logout_url', 'other_service_cert'
        assert false
        done()

    xit 'can assert', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      idp = new saml2.IdentityProvider 'login_url', 'logout_url', 'other_service_cert'

      async.waterfall [
        (cb_wf) => sp.create_login_url idp, request_body, cb_wf
      ], (err, user) ->
        assert not err?, "Error asserting: #{err}"
        done()

    assert_errors =
      'error1' : 'response1'

    _.each assert_errors, (response_text, error_type) ->
      xit "returns correct 'assert' error for #{error_type} ", (done) ->
        assert false
        done()
