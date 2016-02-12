_             = require 'underscore'
assert        = require 'assert'
async         = require 'async'
zlib          = require 'zlib'
crypto        = require 'crypto'
fs            = require 'fs'
saml2         = require "#{__dirname}/../index"
url           = require 'url'
util          = require 'util'
xmldom        = require 'xmldom'

describe 'saml2', ->
  get_test_file = (filename) ->
    fs.readFileSync("#{__dirname}/data/#{filename}").toString()

  has_attribute = (node, attr_name, attr_value) ->
    _(node.attributes).some (attr) -> attr.name is attr_name and attr.value is attr_value

  describe 'private helpers', ->

    dom_from_test_file = (filename) ->
      (new xmldom.DOMParser()).parseFromString get_test_file filename

    before =>
      @good_response_dom = dom_from_test_file "good_response.xml"

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

      it 'contains an AuthnContext if requested', ->
        { id, xml } = saml2.create_authn_request 'a', 'b', 'c', true, { comparison: 'exact', class_refs: ['context:class']}
        dom = (new xmldom.DOMParser()).parseFromString xml
        authn_request = dom.getElementsByTagName('AuthnRequest')[0]

        requested_authn_context = authn_request.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'RequestedAuthnContext')[0]
        assert _(requested_authn_context.attributes).some (attr) -> attr.name is 'Comparison' and attr.value is 'exact'
        assert.equal requested_authn_context.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AuthnContextClassRef')[0].firstChild.data, 'context:class'

    describe 'create_metadata', ->
      CERT_1 = get_test_file 'test.crt'
      CERT_2 = get_test_file 'test2.crt'

      CERT_1_DATA = saml2.extract_certificate_data CERT_1
      CERT_2_DATA = saml2.extract_certificate_data CERT_2

      METADATA =
        saml2.create_metadata(
          'https://sp.example.com/metadata.xml',
          'https://sp.example.com/assert',
          [CERT_1],
          [CERT_1, CERT_2])

      dom = (new xmldom.DOMParser()).parseFromString METADATA
      entity_descriptor =
        dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'EntityDescriptor')[0]

      it 'contains expected entity id', ->
        assert(
          has_attribute entity_descriptor, 'entityID', 'https://sp.example.com/metadata.xml',
          "Expected to find attribute 'entityID' with value 'https://sp.example.com/metadata.xml'.")

      it 'contains expected key descriptors', ->
        key_descriptors = entity_descriptor.getElementsByTagNameNS(
          'urn:oasis:names:tc:SAML:2.0:metadata', 'KeyDescriptor')

        assert.equal(
          key_descriptors.length, 3, "Expected 3 key descriptors; found #{key_descriptors.length}")

        assert(
          has_attribute key_descriptors[0], 'use', 'signing',
          "Expected 1st key descriptor to have attribute 'use' with value 'signing'.")

        assert(
          has_attribute key_descriptors[1], 'use', 'encryption',
          "Expected 2nd key descriptor to have attribute 'use' with value 'encryption'.")

        assert(
          has_attribute key_descriptors[2], 'use', 'encryption',
          "Expected 3rd key descriptor to have attribute 'use' with value 'encryption'.")

        signing_cert = key_descriptors[0].getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')[0].firstChild
        assert.equal signing_cert, CERT_1_DATA, 'Unexpected value for signing cert.'

        encryption_cert_1 = key_descriptors[1].getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')[0].firstChild
        assert.equal encryption_cert_1, CERT_1_DATA, 'Unexpected value for 1st encryption cert.'

        encryption_cert_2 = key_descriptors[2].getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')[0].firstChild
        assert.equal encryption_cert_2, CERT_2_DATA, 'Unexpected value for 2nd encryption cert.'

      it 'contains expected service URLs', ->
        consumer_service = entity_descriptor.getElementsByTagNameNS(
          'urn:oasis:names:tc:SAML:2.0:metadata', 'AssertionConsumerService')[0]

        assert(
          has_attribute(
            consumer_service, 'Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
          "Expected to find an AssertionConsumerService with POST binding.")

        assert(
          has_attribute consumer_service, 'Location', 'https://sp.example.com/assert',
          "Expected to find an AssertionConsumerService with location
            'htps://sp.example.com/assert'")

        logout_service = entity_descriptor.getElementsByTagNameNS(
          'urn:oasis:names:tc:SAML:2.0:metadata', 'SingleLogoutService')[0]

        assert(
          has_attribute(
            logout_service, 'Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
          "Expected to find an SingleLogoutService with redirect binding.")

        assert(
          has_attribute logout_service, 'Location', 'https://sp.example.com/assert',
          "Expected to find an SingleLogoutService with location 'htps://sp.example.com/assert'")

    describe 'format_pem', ->
      it 'formats an unformatted private key', ->
        raw_private_key = (/-----BEGIN PRIVATE KEY-----([^-]*)-----END PRIVATE KEY-----/g.exec get_test_file("test.pem"))[1]
        formatted_key = saml2.format_pem raw_private_key, 'PRIVATE KEY'
        assert.equal formatted_key.trim(), get_test_file("test.pem").trim()

      it 'does not change an already formatted private key', ->
        formatted_key = saml2.format_pem get_test_file("test.pem"), 'PRIVATE KEY'
        assert.equal formatted_key, get_test_file("test.pem")

    describe 'sign_request', ->
      it 'correctly signs a get request', ->
        signed = saml2.sign_request 'TESTMESSAGE', get_test_file("test.pem")

        verifier = crypto.createVerify 'RSA-SHA256'
        verifier.update 'SAMLRequest=TESTMESSAGE&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256'
        assert verifier.verify(get_test_file("test.crt"), signed.Signature, 'base64'), "Signature is not valid"
        assert.equal signed.SigAlg, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        assert.equal signed.SAMLRequest, 'TESTMESSAGE'

      it 'correctly signs a get response with RelayState', ->
        signed = saml2.sign_request 'TESTMESSAGE', get_test_file("test.pem"), 'TESTSTATE', true

        verifier = crypto.createVerify 'RSA-SHA256'
        verifier.update 'SAMLResponse=TESTMESSAGE&RelayState=TESTSTATE&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256'
        assert verifier.verify(get_test_file("test.crt"), signed.Signature, 'base64'), "Signature is not valid"
        assert signed.SigAlg, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        assert.equal signed.RelayState, 'TESTSTATE'
        assert.equal signed.SAMLResponse, 'TESTMESSAGE'

    describe 'check_saml_signature', ->
      it 'accepts signed xml', ->
        result = saml2.check_saml_signature(get_test_file("good_assertion.xml"), get_test_file("test.crt"))
        assert.deepEqual result, [get_test_file("good_assertion.xml")]

      it 'rejects xml without a signature', ->
        assert.equal null, saml2.check_saml_signature(get_test_file("unsigned_assertion.xml"), get_test_file("test.crt"))

      it 'rejects xml with an invalid signature', ->
        assert.equal null, saml2.check_saml_signature(get_test_file("good_assertion.xml"), get_test_file("test2.crt"))

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
      KEY_1 = get_test_file("test.pem")
      KEY_2 = get_test_file("test2.pem")

      it 'decrypts and extracts an assertion with all availble keys', (done) =>
        saml2.decrypt_assertion @good_response_dom, [KEY_2, KEY_1], (err, result) ->
          assert not err?, "Got error: #{err}"
          assert.equal result, get_test_file("good_response_decrypted.xml")
          done()

      it 'errors if an incorrect key is used', (done) =>
        saml2.decrypt_assertion @good_response_dom, [KEY_2], (err, result) ->
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

    describe 'parse_logout_request', =>
      it 'correctly parses a logout request', =>
        request = saml2.parse_logout_request dom_from_test_file('logout_request.xml')
        assert.equal request.issuer, 'http://idp.example.com/metadata.xml'
        assert.equal request.name_id, 'tstudent'
        assert.equal request.session_index, '_2'

    describe 'get_name_id', ->
      it 'gets the correct NameID', ->
        name_id = saml2.get_name_id dom_from_test_file('good_assertion.xml')
        assert.equal name_id, 'tstudent'

      it 'parses assertions with explicit namespaces', ->
        name_id = saml2.get_name_id dom_from_test_file('good_assertion_explicit_namespaces.xml')
        assert.equal name_id, 'tstudent'

    describe 'get_session_index', ->
      it 'gets the correct session index', ->
        session_index = saml2.get_session_index dom_from_test_file('good_assertion.xml')
        assert.equal session_index, '_3'

    describe 'parse_assertion_attributes', ->
      it 'correctly parses assertion attributes', ->
        expected_attributes =
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': [ 'Test' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [ 'tstudent@example.com' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier': [ 'tstudent' ]
            'http://schemas.xmlsoap.org/claims/Group': [ 'CN=Students,CN=Users,DC=idp,DC=example,DC=com' ]
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': [ 'Student' ]
            'http://schemas.xmlsoap.org/claims/CommonName': [ 'Test Student' ]

        attributes = saml2.parse_assertion_attributes dom_from_test_file('good_assertion.xml')
        assert.deepEqual attributes, expected_attributes

      it 'correctly parses assertion attributes', ->
        expected_attributes =
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': [ '' ]

        attributes = saml2.parse_assertion_attributes dom_from_test_file('empty_attribute_value.xml')
        assert.deepEqual attributes, expected_attributes

      it 'correctly parses no assertion attributes', ->
        attributes = saml2.parse_assertion_attributes dom_from_test_file('blank_assertion.xml')
        assert.deepEqual attributes, {}

    describe 'set option defaults', ->
      it 'sets defaults in the correct order', ->
        options_top =
          option1: "top"
          option4: "top"
        options_middle =
          option1: "middle"
          option2: "middle"
          option5: "middle"
        options_bottom =
          option1: "bottom"
          option2: "bottom"
          option3: "bottom"
          option6: "bottom"
        expected_options =
          option1: "top"
          option2: "middle"
          option3: "bottom"
          option4: "top"
          option5: "middle"
          option6: "bottom"
        actual_options = saml2.set_option_defaults options_top, options_middle, options_bottom
        assert.deepEqual actual_options, expected_options

  describe 'post_assert', ->
    it 'returns a user object when passed a valid AuthnResponse', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test2.pem')
        alt_private_keys: get_test_file('test.pem')
        certificate: get_test_file('test2.crt')
        alt_certs: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: [ get_test_file('test.crt'), get_test_file('test2.crt') ]
      request_options =
        request_body:
          SAMLResponse: get_test_file("post_response.xml")

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.post_assert idp, request_options, (err, response) ->
        assert not err?, "Got error: #{err}"
        expected_response =
          response_header:
            id: '_2'
            in_response_to: '_1'
            destination: 'https://sp.example.com/assert'
          type: 'authn_response'
          user:
            name_id: 'tstudent'
            session_index: '_3'
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

        assert.deepEqual response, expected_response
        done()

    it 'errors if passed invalid data', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: get_test_file('test.crt')
      resquest_options =
        request_body:
          SAMLResponse: 'FAIL'

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.post_assert idp, resquest_options, (err, user) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

    it "rejects a signed response if the assertion isn't signed", (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url: 'https://idp.example.com/logout'
        certificates: [ get_test_file('test.crt') ]
        allow_unencrypted_assertion: true
      request_options =
        request_body:
          SAMLResponse: get_test_file("response_unsigned_assertion.xml")

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.post_assert idp, request_options, (err, response) ->
        assert (err instanceof Error), "Did not get expected error."
        done()

    it 'correctly parses an empty NameID', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test2.pem')
        alt_private_keys: get_test_file('test.pem')
        certificate: get_test_file('test2.crt')
        alt_certs: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: [ get_test_file('test.crt'), get_test_file('test2.crt') ]
      request_options =
        ignore_signature: true
        allow_unencrypted_assertion: true
        request_body:
          SAMLResponse: get_test_file("empty_nameid.xml")

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.post_assert idp, request_options, (err, response) ->
        assert not err?, "Got error: #{err}"
        expected_response =
          response_header:
            id: '_2'
            in_response_to: '_1'
            destination: 'https://sp.example.com/assert'
          type: 'authn_response'
          user:
            name_id: undefined
            session_index: '_4'
            attributes: {}

        assert.deepEqual response, expected_response
        done()

  describe 'redirect assert', ->

    it 'returns a user object with passed a valid AuthnResponse', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: [ get_test_file('test.crt'), get_test_file('test2.crt') ]
      request_options =
        request_body:
          SAMLResponse: get_test_file("redirect_response.xml")

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.redirect_assert idp, request_options, (err, response) ->
        assert not err?, "Got error: #{err}"
        expected_response =
          response_header:
            id: '_2'
            in_response_to: '_1'
            destination: 'https://sp.example.com/assert'
          type: 'authn_response'
          user:
            name_id: 'tstudent'
            session_index: '_3'
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
        assert.deepEqual response, expected_response
        done()

  describe 'ServiceProvider', ->

    it 'can be constructed', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      sp = new saml2.ServiceProvider sp_options
      done()

    it 'can create login request url', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: 'other_service_cert'

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      async.waterfall [
        (cb_wf) -> sp.create_login_request_url idp, {assert_endpoint:'https://sp.example.com/assert'}, cb_wf
      ], (err, login_url, id) ->
        assert not err?, "Error creating login URL: #{err}"
        parsed_url = url.parse login_url, true
        saml_request = parsed_url.query?.SAMLRequest?
        assert saml_request, 'Could not find SAMLRequest in url query parameters'
        done()

    it 'passes through RelayState in create login request url', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: 'other_service_cert'

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.create_login_request_url idp, {assert_endpoint: 'https://sp.example.com/assert', relay_state: 'Some Relay State!'}, (err, login_url, id) ->
        assert not err?, "Error creating login URL: #{err}"
        parsed_url = url.parse login_url, true
        assert.equal parsed_url.query?.RelayState, 'Some Relay State!'
        done()

    it 'can specify a nameid format in create login request url', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: 'other_service_cert'
      request_options = 
        assert_endpoint: 'https://sp.example.com/assert'
        relay_state: 'Some Relay State!'
        nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.create_login_request_url idp, request_options, (err, login_url, id) ->
        assert not err?, "Error creating login URL: #{err}"
        parsed_url = url.parse login_url, true
        saml_request = new Buffer(parsed_url.query?.SAMLRequest, 'base64')
        zlib.inflateRaw saml_request, (err, result) ->
          assert.notEqual result.toString('utf8').indexOf("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), -1
          done()

    it 'requests a nameid format type of urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified if none is specified', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: 'other_service_cert'
      request_options = 
        assert_endpoint: 'https://sp.example.com/assert'
        relay_state: 'Some Relay State!'

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      sp.create_login_request_url idp, request_options, (err, login_url, id) ->
        assert not err?, "Error creating login URL: #{err}"
        parsed_url = url.parse login_url, true
        saml_request = new Buffer(parsed_url.query?.SAMLRequest, 'base64')
        zlib.inflateRaw saml_request, (err, result) ->
          assert.notEqual result.toString('utf8').indexOf("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"), -1
          done()

    it 'can create logout request url using an idp', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_login_url: 'https://idp.example.com/login'
        sso_logout_url:  'https://idp.example.com/logout'
        certificates: get_test_file('test.crt')
      request_options =
        name_id: 'name_id'
        session_index: 'session_index'
        sign_get_request: true

      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      async.waterfall [
        (cb_wf) -> sp.create_logout_request_url idp, request_options, cb_wf
      ], (err, logout_url) ->
        assert not err?, "Error creating logout URL: #{err}"
        parsed_url = url.parse logout_url, true
        assert parsed_url?.query?.SAMLRequest?, 'Could not find SAMLRequest in url query parameters'
        assert parsed_url?.query?.Signature?, 'LogoutRequest is not signed'
        done()

    it 'can create logout request url using an string sso_logout_url', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      idp_options =
        sso_logout_url : 'https://idp.example.com/logout'
      request_options =
        name_id: 'name_id'
        session_index: 'session_index'
        sign_get_request: true
      
      sp = new saml2.ServiceProvider sp_options
      idp = new saml2.IdentityProvider idp_options

      async.waterfall [
        (cb_wf) -> sp.create_logout_request_url idp, request_options, cb_wf
      ], (err, logout_url) ->
        assert not err?, "Error creating logout URL: #{err}"
        parsed_url = url.parse logout_url, true
        assert parsed_url?.query?.SAMLRequest?, 'Could not find SAMLRequest in url query parameters'
        assert parsed_url?.query?.Signature?, 'LogoutRequest is not signed'
        done()

    it 'can create logout response url using an idp', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      sso_logout_url = 'https://idp.example.com/logout'
      request_options =
        in_response_to: '_1'
        sign_get_request: true

      sp = new saml2.ServiceProvider sp_options

      async.waterfall [
        (cb_wf) -> sp.create_logout_response_url sso_logout_url, request_options, cb_wf
      ], (err, logout_url) ->
        assert not err?, "Error creating response logout URL: #{err}"
        parsed_url = url.parse logout_url, true
        assert parsed_url?.query?.SAMLResponse?, 'Could not find SAMLResponse in url query parameters'
        assert parsed_url?.query?.Signature?, 'LogoutResponse is not signed'
        done()

    it 'can create logout response url using an string sso_logout_url', (done) ->
      sp_options =
        entity_id: 'https://sp.example.com/metadata.xml'
        private_key: get_test_file('test.pem')
        certificate: get_test_file('test.crt')
        assert_endpoint: 'https://sp.example.com/assert'
      request_options =
        in_response_to: '_1'
        sign_get_request: true

      sso_logout_url = 'https://idp.example.com/logout'
      sp = new saml2.ServiceProvider sp_options

      async.waterfall [
        (cb_wf) -> sp.create_logout_response_url sso_logout_url, request_options, cb_wf
      ], (err, logout_url) ->
        assert not err?, "Error creating response logout URL: #{err}"
        parsed_url = url.parse logout_url, true
        assert parsed_url?.query?.SAMLResponse?, 'Could not find SAMLResponse in url query parameters'
        assert parsed_url?.query?.Signature?, 'LogoutResponse is not signed'
        done()

    it 'can create metadata', (done) ->
      done()
