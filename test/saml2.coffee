_             = require 'underscore'
assert        = require 'assert'
async         = require 'async'
fs            = require 'fs'
saml2         = require "#{__dirname}/../index"
url           = require 'url'
util          = require 'util'
xmldom        = require 'xmldom'

describe 'saml2', ->
  get_test_file = (filename) ->
    fs.readFileSync("#{__dirname}/data/#{filename}").toString()

  dom_from_test_file = (filename) ->
    (new xmldom.DOMParser()).parseFromString get_test_file filename

  before =>
    @good_response_dom = dom_from_test_file "good_response.xml"

  describe 'xml metadata', ->
    it.skip 'is valid xml', (done) ->
      assert false
      done()
    it.skip 'contains expected fields', (done) ->
      assert false
      done()

  # Login
  describe 'login url', ->
    it.skip 'creates an AuthRequest that is base64 encoded and compressed', (done) ->
      assert false
      done()
    it.skip 'includes relay URL', (done) ->
      assert false
      done()
    it.skip 'is configured according to the identity provider', (done) ->
      assert false
      done()

  # Auth Request, before it is compressed and base-64 encoded
  describe 'create_authn_request', ->
    it 'contains expected fields', ->
      { id, xml } = saml2.create_authn_request 'https://sp.example.com/metadata.xml', 'https://sp.example.com/assert', 'https://idp.example.com/login'
      dom = (new xmldom.DOMParser()).parseFromString xml
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

  describe 'create_metadata', ->
    it 'contains expected fields', ->
      cert = fs.readFileSync "#{__dirname}/data/test.crt"
      cert2 = fs.readFileSync "#{__dirname}/data/test2.crt"

      metadata = saml2.create_metadata 'https://sp.example.com/metadata.xml', 'https://sp.example.com/assert', cert, cert2
      dom = (new xmldom.DOMParser()).parseFromString metadata

      entity_descriptor = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'EntityDescriptor')[0]
      assert _(entity_descriptor.attributes).some((attr) -> attr.name is 'entityID' and attr.value is 'https://sp.example.com/metadata.xml')
        , "Expected to find attribute 'entityID' with value 'https://sp.example.com/metadata.xml'."

      assert _(entity_descriptor.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'AssertionConsumerService')).some((assertion) ->
        _(assertion.attributes).some((attr) -> attr.name is 'Binding' and attr.value is 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') and
          _(assertion.attributes).some((attr) -> attr.name is 'Location' and attr.value is 'https://sp.example.com/assert'))
        , "Expected to find an AssertionConsumerService with POST binding and location 'https://sp.example.com/assert'"

  describe 'check_saml_signature', ->
    it 'accepts signed xml', (done) ->
      saml2.check_saml_signature get_test_file("good_assertion.xml"), get_test_file("test.crt"), (err) ->
        assert not err?, "Got error: #{err}"
        done()

    it 'rejects xml without a signature', (done) ->
      saml2.check_saml_signature get_test_file("unsigned_assertion.xml"), get_test_file("test.crt"), (err) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

    it 'rejects xml with an invalid signature', (done) ->
      saml2.check_saml_signature get_test_file("good_assertion.xml"), get_test_file("test2.crt"), (err) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

  describe 'check_status_success', =>
    it 'accepts a valid success status', =>
      assert saml2.check_status_success(@good_response_dom), "Did not get 'true' for valid response."

    it 'rejects a missing success status', ->
      assert not saml2.check_status_success(dom_from_test_file("response_error_status.xml")), "Did not get 'false' for invalid response."

    it 'rejects a missing status', ->
      assert not saml2.check_status_success(dom_from_test_file("response_no_status.xml")), "Did not get 'false' for invalid response."

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

  describe 'decrypt_assertion', =>
    it 'decrypts and extracts an assertion', (done) =>
      key = get_test_file("test.pem")
      saml2.decrypt_assertion @good_response_dom, key, (err, result) ->
        assert not err?, "Got error: #{err}"
        assert.equal result, get_test_file("good_response_decrypted.xml")
        done()

    it 'errors if an incorrect key is used', (done) =>
      key = get_test_file("test2.pem")
      saml2.decrypt_assertion @good_response_dom, key, (err, result) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

  describe 'parse_response_header', =>
    it 'correctly parses a response header', =>
      response = saml2.parse_response_header @good_response_dom
      assert.equal response.destination, 'https://sp.example.com/assert'
      assert.equal response.in_response_to, '_1'

    it 'errors if there is no response', ->
      # An assertion is not a response, so this should fail.
      assert.throws -> saml2.parse_response_header dom_from_test_file("good_assertion.xml")

    it 'errors if given a response with the wrong version', ->
      assert.throws -> saml2.parse_response_header dom_from_test_file("response_bad_version.xml")

  describe 'parse_assertion_attributes', ->
    it 'correctled parses assertion attributes', ->
      expected_attributes =
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': [ 'Test' ]
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [ 'tstudent@example.com' ]
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier': [ 'tstudent' ]
          'http://schemas.xmlsoap.org/claims/Group': [ 'CN=Students,CN=Users,DC=idp,DC=example,DC=com' ]
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': [ 'Student' ]
          'http://schemas.xmlsoap.org/claims/CommonName': [ 'Test Student' ]

      attributes = saml2.parse_assertion_attributes dom_from_test_file('good_assertion.xml')
      assert.deepEqual attributes, expected_attributes

  # Assert
  describe 'assert', ->
    it 'returns a user object when passed a valid AuthnResponse', (done) ->
      sp = new saml2.ServiceProvider 'https://sp.example.com/metadata.xml', get_test_file('test.pem'), get_test_file('test.crt')
      idp = new saml2.IdentityProvider 'https://idp.example.com/login', 'https://idp.example.com/logout', get_test_file('test.crt')

      sp.assert idp, { SAMLResponse: get_test_file("post_response.xml") }, (err, user) ->
        assert not err?, "Got error: #{err}"

        expected_user =
          response_header:
            in_response_to: '_1'
            destination: 'https://sp.example.com/assert'
          given_name: 'Test',
          email: 'tstudent@example.com',
          ppid: 'tstudent',
          group: 'CN=Students,CN=Users,DC=idp,DC=example,DC=com',
          surname: 'Student',
          common_name: 'Test Student',
          attributes:
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': [ 'Test' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [ 'tstudent@example.com' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier': [ 'tstudent' ]
            'http://schemas.xmlsoap.org/claims/Group': [ 'CN=Students,CN=Users,DC=idp,DC=example,DC=com' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': [ 'Student' ]
            'http://schemas.xmlsoap.org/claims/CommonName': [ 'Test Student' ]

        assert.deepEqual user, expected_user
        done()

    it 'errors if passed invalid data', (done) ->
      sp = new saml2.ServiceProvider 'https://sp.example.com/metadata.xml', get_test_file('test.pem'), get_test_file('test.crt')
      idp = new saml2.IdentityProvider 'https://idp.example.com/login', 'https://idp.example.com/logout', get_test_file('test.crt')

      sp.assert idp, { SAMLResponse: 'FAIL' }, (err, user) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

  describe 'check_signature', ->
    it.skip 'verifies document is signed', (done) ->
      assert false
      done()

    # Other tests that *strictly* enforce the signature. For example...
    # - checks that correct part of document is signed
    # - checks that correct part of document is signed with correct signature

  describe 'IdentityProvider', ->
    it.skip 'validates configuration passed to constructor (urls, certificate)', (done) ->
      assert false
      done()

  describe 'ServiceProvider', ->
    it 'can be constructed', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      done()

    it.skip 'validates configuration given to constructor (private key, certificate)', (done) ->
      assert false
      done()

    it 'can create login url', (done) ->
      sp = new saml2.ServiceProvider 'private_key', 'cert'
      idp = new saml2.IdentityProvider 'https://idp.example.com/login', 'https://idp.example.com/logout', 'other_service_cert'

      async.waterfall [
        (cb_wf) -> sp.create_login_url idp, 'https://sp.example.com/assert', cb_wf
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
      it.skip "returns correct 'login_url' error for #{error_type} ", (done) ->
        sp = new saml2.ServiceProvider 'private_key', 'cert'
        idp = new saml2.IdentityProvider 'login_url', 'logout_url', 'other_service_cert'
        assert false
        done()

    assert_errors =
      'error1' : 'response1'

    _.each assert_errors, (response_text, error_type) ->
      it.skip "returns correct 'assert' error for #{error_type} ", (done) ->
        assert false
        done()
