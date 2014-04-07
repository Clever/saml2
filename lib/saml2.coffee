_             = require 'underscore'
async         = _.extend require('async'), require('async-ext')
crypto        = require 'crypto'
{parseString} = require 'xml2js'
url           = require 'url'
util          = require 'util'
xmlbuilder    = require 'xmlbuilder'
xmlcrypto     = require 'xml-crypto'
xmldom        = require 'xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'

# Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created
# request.
create_authn_request = (issuer, assert_endpoint, destination) ->
  id = '_' + crypto.randomBytes(21).toString('hex')
  xml = xmlbuilder.create
    AuthnRequest:
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:protocol'
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
      '@Version': '2.0'
      '@ID': id
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      '@AssertionConsumerServiceURL': assert_endpoint
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      'saml:Issuer': issuer
      NameIDPolicy:
        '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        '@AllowCreate': 'true'
  .end()
  { id, xml }

# Creates metadata and returns it as a string of xml. The metadata has one POST assertion endpoint.
create_metadata = (issuer, assert_endpoint, signing_certificate, encryption_certificate) ->
  xmlbuilder.create
    'md:EntityDescriptor':
      '@xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata'
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'
      '@entityID': issuer
      'md:SPSSODescriptor': [
          '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
          { 'md:KeyDescriptor': certificate_to_keyinfo('signing', signing_certificate) },
          { 'md:KeyDescriptor': certificate_to_keyinfo('encryption', encryption_certificate) },
          'md:AssertionConsumerService':
            '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            '@Location': assert_endpoint
            '@index': '0'
        ]
  .end()

# Creates a LogoutRequest and returns it as a string of xml.
create_logout_request = (issuer, name_id, session_index, destination) ->
  xmlbuilder.create
    'samlp:LogoutRequest':
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
      '@ID': '_' + crypto.randomBytes(21).toString('hex')
      '@Version': '2.0'
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      'saml:Issuer': issuer
      'saml:NameID': name_id
      'samlp:SessionIndex': session_index
  .end()

# Takes a compressed/base64 enoded @saml_request and @private_key and signs the request using RSA-SHA1. It returns the
# result as an object containing the query parameters.
sign_get_request = (saml_request, private_key) ->
  data = "SAMLRequest=" + encodeURIComponent(saml_request) + "&SigAlg=" + encodeURIComponent('http://www.w3.org/2000/09/xmldsig#rsa-sha1')
  sign = crypto.createSign 'RSA-SHA1'
  sign.update(data)

  {
    SAMLRequest: saml_request
    SigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    Signature: sign.sign(private_key, 'base64')
  }

# Converts a pem certificate to a KeyInfo object for use with XML.
certificate_to_keyinfo = (use, certificate) ->
  cert_data = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec certificate
  throw new Error('Invalid Certificate') if cert_data?.length is 0

  {
    '@use': use
    'ds:KeyInfo':
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'
      'ds:X509Data':
        'ds:X509Certificate':
          cert_data[1].replace(/[\r\n|\n]/g, '')
  }

# This function calls @cb with no error if an XML document is signed with the provided cert. This is NOT sufficient for
# signature checks as it doesn't verify the signature is signing the important content, nor is it preventing the
# parsing of unsigned content.
check_saml_signature = (xml, certificate, cb) ->
  doc = (new xmldom.DOMParser()).parseFromString(xml)

  signature = xmlcrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")
  return cb new Error("Expected 1 Signature; found #{signature.length}") unless signature.length is 1
  sig = new xmlcrypto.SignedXml()
  sig.keyInfoProvider = getKey: -> certificate
  sig.loadSignature signature[0].toString()
  return cb null if sig.checkSignature(xml)
  cb new Error("SAML Assertion signature check failed!")

# Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
check_status_success = (dom) ->
  status = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Status')
  return false unless status.length is 1
  for status_code in status[0].childNodes
    if status_code.attributes?
      for attr in status_code.attributes
        return true if attr.name is 'Value' and attr.value is 'urn:oasis:names:tc:SAML:2.0:status:Success'
  false

to_error = (err) ->
  return null unless err?
  return new Error(util.inspect err) unless err instanceof Error
  err

# Takes in an xml @dom of an object containing an EncryptedAssertion and attempts to decrypt it using the @private_key.
# @cb will be called with an error if the decryption fails, or the EncryptedAssertion cannot be found. If successful,
# it will be called with the decrypted data as a string.
decrypt_assertion = (dom, private_key, cb) ->
  # This is needed because xmlenc sometimes throws an exception, and sometimes calls the passed in callback.
  cb = _.wrap cb, (fn, err, args...) -> setTimeout (-> fn to_error(err), args...), 0

  try
    encrypted_assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'EncryptedAssertion')
    return cb new Error("Expected 1 EncryptedAssertion; found #{encrypted_assertion.length}.") unless encrypted_assertion.length is 1

    encrypted_data = encrypted_assertion[0].getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')
    return cb new Error("Expected 1 EncryptedData inside EncryptedAssertion; found #{encrypted_data.length}.") unless encrypted_data.length is 1

    xmlenc.decrypt encrypted_data[0].toString(), (key: private_key), cb
  catch err
    cb new Error("Decrypt failed: #{util.inspect err}")

# Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
# InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
# appear to be valid.
parse_response_header = (dom) ->
  response = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Response')
  throw new Error("Expected 1 Response; found #{response.length}") unless response.length is 1

  response_header = {}
  for attr in response[0].attributes
    switch attr.name
      when "Version"
        throw new Error "Invalid SAML Version #{attr.value}" unless attr.value is "2.0"
      when "Destination"
        response_header.destination = attr.value
      when "InResponseTo"
        response_header.in_response_to = attr.value
  response_header

# Takes in an xml @dom of an object containing a SAML Assertion and returns the NameID. If there is no NameID found,
# it will return null. It will throw an error if the Assertion is missing or does not appear to be valid.
get_name_id = (dom) ->
  assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  subject = assertion[0].getElementsByTagName('Subject')
  throw new Error("Expected 1 Subject; found #{subject.length}") unless subject.length is 1

  nameid = subject[0].getElementsByTagName('NameID')
  return null unless nameid.length is 1

  nameid[0].firstChild?.data

# Takes in an xml @dom of an object containing a SAML Assertion and returns the SessionIndex. It will throw an error
# if there is no SessionIndex, no Assertion, or the Assertion does not appear to be valid.
get_session_index = (dom) ->
  assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  authn_statement = assertion[0].getElementsByTagName('AuthnStatement')
  throw new Error("Expected 1 AuthnStatement; found #{authn_statement.length}") unless authn_statement.length is 1

  for attr in authn_statement[0].attributes
    if attr.name is 'SessionIndex'
      return attr.value

  throw new Error("SessionIndex not an attribute of AuthnStatement.")

# Takes in an xml @dom of an object containing a SAML Assertion and returns and object containing the attributes
# contained within the Assertion. It will throw an error if the Assertion is missing or does not appear to be valid.
parse_assertion_attributes = (dom) ->
  assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  attribute_statement = assertion[0].getElementsByTagName('AttributeStatement')
  throw new Error("Expected 1 AttributeStatement inside Assertion; found #{attribute_statement.length}") unless attribute_statement.length is 1

  assertion_attributes = {}
  for attribute in attribute_statement[0].getElementsByTagName('Attribute')
    for attr in attribute.attributes
      if attr.name is 'Name'
        attribute_name = attr.value
    throw new Error("Invalid attribute without name") unless attribute_name?
    assertion_attributes[attribute_name] = _(attribute.getElementsByTagName('AttributeValue')).map (attribute_value) -> attribute_value.childNodes[0].data
  assertion_attributes

# Takes in an object containing SAML Assertion Attributes and returns an object with certain common attributes changed
# into nicer names. Attributes that are not expected are ignored, and attributes with more than one value with have
# all values except the first one dropped.
pretty_assertion_attributes = (assertion_attributes) ->
  claim_map =
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "given_name"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "name"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "upn"
    "http://schemas.xmlsoap.org/claims/CommonName": "common_name"
    "http://schemas.xmlsoap.org/claims/Group": "group"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "role"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "surname"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier": "ppid"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "name_id"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod": "authentication_method"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/denyonlysid": "deny_only_group_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid": "deny_only_primary_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid": "deny_only_primary_group_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid": "group_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid": "primary_group_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid": "primary_sid"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname": "windows_account_name"

  _(assertion_attributes)
    .chain()
    .pairs()
    .filter(([k, v]) -> (claim_map[k]? and v.length > 0))
    .map(([k, v]) -> [claim_map[k], v[0]])
    .object()
    .value()

module.exports.ServiceProvider =
  class ServiceProvider
    constructor: (@issuer, @private_key, @certificate) ->

    # -- Required
    # Returns a redirect URL, at which a user can login, and the ID of the request.
    create_login_url: (identity_provider, assert_endpoint, cb) =>
      { id, xml } = create_authn_request @issuer, assert_endpoint, identity_provider.sso_login_url
      zlib.deflateRaw xml, (err, deflated) ->
        return cb err if err?
        uri = url.parse identity_provider.sso_login_url
        uri.query =
          SAMLRequest: deflated.toString 'base64'
        cb null, url.format(uri), id

    # Returns user object, if the login attempt was valid.
    assert: (identity_provider, request_body, get_request, cb) ->
      unless request_body?.SAMLResponse?
        return setImmediate cb, new Error("Request body does not contain SAMLResponse.")

      if _.isFunction(get_request) and not cb?
        cb = get_request
        get_request = false

      saml_response = null
      decrypted_assertion = null

      user = {}

      async.waterfall [
        (cb_wf) ->
          raw = new Buffer(request_body.SAMLResponse, 'base64')
          # For GET requests, it's necessary to inflate the response before parsing it.
          if (get_request)
            return zlib.inflateRaw raw, cb_wf
          setImmediate cb_wf, null, raw
        (response, cb_wf) ->
          saml_response = (new xmldom.DOMParser()).parseFromString(response.toString())
          async.lift(parse_response_header) saml_response, cb_wf
        (response_header, cb_wf) =>
          user = { response_header }
          cb_wf new Error("SAML Response was not success!") unless check_status_success(saml_response)
          decrypt_assertion saml_response, @private_key, cb_wf
        (result, cb_wf) ->
          decrypted_assertion = (new xmldom.DOMParser()).parseFromString(result)
          check_saml_signature result, identity_provider.certificate, cb_wf
        (cb_wf) -> async.lift(get_name_id) decrypted_assertion, cb_wf
        (name_id, cb_wf) ->
          user.name_id = name_id
          async.lift(get_session_index) decrypted_assertion, cb_wf
        (session_index, cb_wf) ->
          user.session_index = session_index
          async.lift(parse_assertion_attributes) decrypted_assertion, cb_wf
        (assertion_attributes, cb_wf) ->
          user = _.extend user, pretty_assertion_attributes(assertion_attributes)
          user = _.extend user, attributes: assertion_attributes
          cb_wf null, user
      ], cb

    # -- Optional
    # Returns a redirect URL, at which a user is logged out.
    create_logout_url: (user, identity_provider, cb) =>
      xml = create_logout_request @issuer, user.name_id, user.session_index, identity_provider.sso_logout_url
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        uri = url.parse identity_provider.sso_logout_url
        uri.query = sign_get_request deflated.toString('base64'), @private_key
        cb null, url.format(uri)

    # Returns XML metadata, used during initial SAML configuration
    create_metadata: (identity_provider, assert_endpoint) =>
      create_metadata @issuer, assert_endpoint, @certificate, @certificate

module.exports.IdentityProvider =
  class IdentityProvider
    constructor: (@sso_login_url, @sso_logout_url, @certificate) ->

if process.env.NODE_ENV is "test"
  module.exports.create_authn_request = create_authn_request
  module.exports.create_metadata = create_metadata
  module.exports.check_saml_signature = check_saml_signature
  module.exports.check_status_success = check_status_success
  module.exports.decrypt_assertion = decrypt_assertion
  module.exports.parse_response_header = parse_response_header
  module.exports.parse_assertion_attributes = parse_assertion_attributes
  module.exports.get_name_id = get_name_id
  module.exports.get_session_index = get_session_index
  module.exports.pretty_assertion_attributes = pretty_assertion_attributes
