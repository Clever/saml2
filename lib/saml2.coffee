_             = require 'underscore'
async         = _.extend require('async'), require('async-ext')
crypto        = require 'crypto'
debug         = require('debug') 'saml2'
{parseString} = require 'xml2js'
url           = require 'url'
util          = require 'util'
xmlbuilder    = require 'xmlbuilder'
xmlcrypto     = require 'xml-crypto'
xmldom        = require 'xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'

XMLNS =
  SAML: 'urn:oasis:names:tc:SAML:2.0:assertion'
  SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol'
  MD: 'urn:oasis:names:tc:SAML:2.0:metadata'
  DS: 'http://www.w3.org/2000/09/xmldsig#'
  XENC: 'http://www.w3.org/2001/04/xmlenc#'

class SAMLError extends Error
  constructor: (@message, @extra) ->
    super @message

# Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created
# request.
create_authn_request = (issuer, assert_endpoint, destination, force_authn, context) ->
  if context?
    context_element = _(context.class_refs).map (class_ref) -> 'saml:AuthnContextClassRef': class_ref
    context_element.push '@Comparison': context.comparison

  id = '_' + crypto.randomBytes(21).toString('hex')
  xml = xmlbuilder.create
    AuthnRequest:
      '@xmlns': XMLNS.SAMLP
      '@xmlns:saml': XMLNS.SAML
      '@Version': '2.0'
      '@ID': id
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      '@AssertionConsumerServiceURL': assert_endpoint
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      '@ForceAuthn': force_authn
      'saml:Issuer': issuer
      NameIDPolicy:
        '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        '@AllowCreate': 'true'
      RequestedAuthnContext: context_element
  .end()
  { id, xml }

# Creates metadata and returns it as a string of xml. The metadata has one POST assertion endpoint.
create_metadata = (issuer, assert_endpoint, signing_certificate, encryption_certificate) ->
  xmlbuilder.create
    'md:EntityDescriptor':
      '@xmlns:md': XMLNS.MD
      '@xmlns:ds': XMLNS.DS
      '@entityID': issuer
      'md:SPSSODescriptor': [
          '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
          { 'md:KeyDescriptor': certificate_to_keyinfo('signing', signing_certificate) },
          { 'md:KeyDescriptor': certificate_to_keyinfo('encryption', encryption_certificate) },
          'md:AssertionConsumerService':
            '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            '@Location': assert_endpoint
            '@index': '0'
          'md:SingleLogoutService':
            '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            '@Location': assert_endpoint
        ]
  .end()

# Creates a LogoutRequest and returns it as a string of xml.
create_logout_request = (issuer, name_id, session_index, destination) ->
  xmlbuilder.create
    'samlp:LogoutRequest':
      '@xmlns:samlp': XMLNS.SAMLP
      '@xmlns:saml': XMLNS.SAML
      '@ID': '_' + crypto.randomBytes(21).toString('hex')
      '@Version': '2.0'
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      'saml:Issuer': issuer
      'saml:NameID': name_id
      'samlp:SessionIndex': session_index
  .end()

# Creates a LogoutResponse and returns it as a string of xml.
create_logout_response = (issuer, in_response_to, destination, status='urn:oasis:names:tc:SAML:2.0:status:Success') ->
  xmlbuilder.create(
    {'samlp:LogoutResponse':
        '@Destination': destination
        '@ID': '_' + crypto.randomBytes(21).toString('hex')
        '@InResponseTo': in_response_to
        '@IssueInstant': (new Date()).toISOString()
        '@Version': '2.0'
        '@xmlns:samlp': XMLNS.SAMLP
        '@xmlns:saml': XMLNS.SAML
        'saml:Issuer': issuer
        'samlp:Status':
          'samlp:StatusCode': '@Value': status
    }, { headless: true }
    ).end()

# Takes a base64 encoded @key and returns it formatted with newlines and a PEM header according to @type. If it already
# has a PEM header, it will just return the original key.
format_pem = (key, type) ->
  return key if (/-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g.exec(key))?
  return "-----BEGIN #{type.toUpperCase()}-----\n" + key.match(/.{1,64}/g).join("\n") + "\n-----END #{type.toUpperCase()}-----"

# Takes a compressed/base64 enoded @saml_request and @private_key and signs the request using RSA-SHA256. It returns
# the result as an object containing the query parameters.
sign_get_request = (saml_request, private_key, relay_state, response=false) ->
  action = if response then "SAMLResponse" else "SAMLRequest"
  data = "#{action}=" + encodeURIComponent(saml_request)
  if relay_state
    data += "&RelayState=" + encodeURIComponent(relay_state)
  data += "&SigAlg=" + encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')

  saml_request_data = "#{action}=" + encodeURIComponent(saml_request)
  relay_state_data = if relay_state? then "&RelayState=" + encodeURIComponent(relay_state) else ""
  sigalg_data = "&SigAlg=" + encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
  sign = crypto.createSign 'RSA-SHA256'
  sign.update(saml_request_data + relay_state_data + sigalg_data)

  if response
    saml_response_out = saml_request
  else
    saml_request_out = saml_request unless response

  {
    SAMLResponse: saml_response_out
    SAMLRequest: saml_request_out
    RelayState: relay_state
    SigAlg: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    Signature: sign.sign(format_pem(private_key, 'PRIVATE KEY'), 'base64')
  }

# Converts a pem certificate to a KeyInfo object for use with XML.
certificate_to_keyinfo = (use, certificate) ->
  cert_data = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec certificate
  cert_data = if cert_data? then cert_data[1] else certificate
  throw new Error('Invalid Certificate') unless cert_data?

  {
    '@use': use
    'ds:KeyInfo':
      '@xmlns:ds': XMLNS.DS
      'ds:X509Data':
        'ds:X509Certificate':
          cert_data.replace(/[\r\n|\n]/g, '')
  }

# This function calls @cb with no error if an XML document is signed with the provided cert. This is NOT sufficient for
# signature checks as it doesn't verify the signature is signing the important content, nor is it preventing the
# parsing of unsigned content.
check_saml_signature = (xml, certificate, cb) ->
  doc = (new xmldom.DOMParser()).parseFromString(xml)

  signature = xmlcrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")
  return false unless signature.length is 1
  sig = new xmlcrypto.SignedXml()
  sig.keyInfoProvider = getKey: -> format_pem(certificate, 'CERTIFICATE')
  sig.loadSignature signature[0].toString()
  return sig.checkSignature xml

# Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
check_status_success = (dom) ->
  status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status')
  return false unless status.length is 1
  for status_code in status[0].childNodes
    if status_code.attributes?
      for attr in status_code.attributes
        return true if attr.name is 'Value' and attr.value is 'urn:oasis:names:tc:SAML:2.0:status:Success'
  false

get_status = (dom) ->
  status_list = {}
  status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status')
  return status_list unless status.length is 1

  for status_code in status[0].childNodes
    if status_code.attributes?
      for attr in status_code.attributes
        if attr.name is 'Value'
          top_status = attr.value
          status_list[top_status] ?= []
    for sub_status_code in status_code.childNodes
      if sub_status_code.attributes?
        for attr in sub_status_code.attributes
          if attr.name is 'Value'
            status_list[top_status].push attr.value
  status_list

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
    encrypted_assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'EncryptedAssertion')
    return cb new Error("Expected 1 EncryptedAssertion; found #{encrypted_assertion.length}.") unless encrypted_assertion.length is 1

    encrypted_data = encrypted_assertion[0].getElementsByTagNameNS(XMLNS.XENC, 'EncryptedData')
    return cb new Error("Expected 1 EncryptedData inside EncryptedAssertion; found #{encrypted_data.length}.") unless encrypted_data.length is 1

    xmlenc.decrypt encrypted_data[0].toString(), (key: format_pem(private_key, 'PRIVATE KEY')), cb
  catch err
    cb new Error("Decrypt failed: #{util.inspect err}")

# Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
# InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
# appear to be valid.
parse_response_header = (dom) ->
  for response_type in ['Response', 'LogoutResponse', 'LogoutRequest']
    response = dom.getElementsByTagNameNS(XMLNS.SAMLP, response_type)
    break if response.length > 0
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
      when "ID"
        response_header.id = attr.value
  response_header

# Takes in an xml @dom of an object containing a SAML Assertion and returns the NameID. If there is no NameID found,
# it will return null. It will throw an error if the Assertion is missing or does not appear to be valid.
get_name_id = (dom) ->
  assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  subject = assertion[0].getElementsByTagNameNS(XMLNS.SAML, 'Subject')
  throw new Error("Expected 1 Subject; found #{subject.length}") unless subject.length is 1

  nameid = subject[0].getElementsByTagNameNS(XMLNS.SAML, 'NameID')
  return null unless nameid.length is 1

  nameid[0].firstChild?.data

# Takes in an xml @dom of an object containing a SAML Assertion and returns the SessionIndex. It will throw an error
# if there is no SessionIndex, no Assertion, or the Assertion does not appear to be valid.
get_session_index = (dom) ->
  assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  authn_statement = assertion[0].getElementsByTagNameNS(XMLNS.SAML, 'AuthnStatement')
  throw new Error("Expected 1 AuthnStatement; found #{authn_statement.length}") unless authn_statement.length is 1

  for attr in authn_statement[0].attributes
    if attr.name is 'SessionIndex'
      return attr.value

  throw new Error("SessionIndex not an attribute of AuthnStatement.")

# Takes in an xml @dom of an object containing a SAML Assertion and returns and object containing the attributes
# contained within the Assertion. It will throw an error if the Assertion is missing or does not appear to be valid.
parse_assertion_attributes = (dom) ->
  assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  attribute_statement = assertion[0].getElementsByTagNameNS(XMLNS.SAML, 'AttributeStatement')
  throw new Error("Expected 1 AttributeStatement inside Assertion; found #{attribute_statement.length}") unless attribute_statement.length <= 1
  return {} if attribute_statement.length is 0

  assertion_attributes = {}
  for attribute in attribute_statement[0].getElementsByTagNameNS(XMLNS.SAML, 'Attribute')
    for attr in attribute.attributes
      if attr.name is 'Name'
        attribute_name = attr.value
    throw new Error("Invalid attribute without name") unless attribute_name?
    assertion_attributes[attribute_name] = _(attribute.getElementsByTagNameNS(XMLNS.SAML, 'AttributeValue')).map (attribute_value) -> attribute_value.childNodes[0].data
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

# Takes a dom of a saml_response, a private key used to decrypt it and the certificate of the identity provider that
# issued it and will return a user object containing the attributes or an error if keys are incorrect or the response
# is invalid.
parse_authn_response = (saml_response, sp_private_key, idp_certificates, cb) ->
  user = {}
  decrypted_assertion = null

  async.waterfall [
    (cb_wf) ->
      decrypt_assertion saml_response, sp_private_key, cb_wf
    (result, cb_wf) ->
      debug result
      decrypted_assertion = (new xmldom.DOMParser()).parseFromString(result)
      unless _.some(idp_certificates, (cert) -> check_saml_signature result, cert)
        return cb_wf new Error("SAML Assertion signature check failed! (checked #{idp_certificates.length} certificate(s))")
      cb_wf null
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
      cb_wf null, { user }
  ], cb

parse_logout_request = (dom) ->
  request = dom.getElementsByTagNameNS(XMLNS.SAMLP, "LogoutRequest")
  throw new Error("Expected 1 LogoutRequest; found #{request.length}") unless request.length is 1

  request = {}

  issuer = dom.getElementsByTagNameNS(XMLNS.SAML, 'Issuer')
  request.issuer = issuer[0].firstChild?.data if issuer.length is 1
  name_id = dom.getElementsByTagNameNS(XMLNS.SAML, 'NameID')
  request.name_id = name_id[0].firstChild?.data if name_id.length is 1
  session_index = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'SessionIndex')
  request.session_index = session_index[0].firstChild?.data if session_index.length is 1

  request

module.exports.ServiceProvider =
  class ServiceProvider
    constructor: (@issuer, @private_key, @certificate) ->

    # -- Required
    # Returns a redirect URL, at which a user can login, and the ID of the request.
    create_login_url: (identity_provider, assert_endpoint, relay_state..., cb) =>
      options = relay_state[1]
      relay_state = relay_state[0]

      { id, xml } = create_authn_request @issuer, assert_endpoint, identity_provider.sso_login_url, options?.force_authn, options?.context
      zlib.deflateRaw xml, (err, deflated) ->
        return cb err if err?
        uri = url.parse identity_provider.sso_login_url
        uri.query =
          SAMLRequest: deflated.toString 'base64'
        uri.query.RelayState = relay_state if relay_state?
        cb null, url.format(uri), id

    # Returns an object containing the parsed response.
    assert: (identity_provider, request_body, get_request..., cb) ->
      get_request =  get_request[0]

      unless request_body?.SAMLResponse? or request_body?.SAMLRequest?
        return setImmediate cb, new Error("Request body does not contain SAMLResponse or SAMLRequest.")

      saml_response = null
      decrypted_assertion = null

      response = {}

      async.waterfall [
        (cb_wf) ->
          raw = new Buffer(request_body.SAMLResponse or request_body.SAMLRequest, 'base64')
          # For GET requests, it's necessary to inflate the response before parsing it.
          if (get_request)
            return zlib.inflateRaw raw, cb_wf
          setImmediate cb_wf, null, raw
        (response_buffer, cb_wf) ->
          debug saml_response
          saml_response = (new xmldom.DOMParser()).parseFromString(response_buffer.toString())
          async.lift(parse_response_header) saml_response, cb_wf
        (response_header, cb_wf) =>
          response = { response_header }
          switch
            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'Response').length is 1
              unless check_status_success(saml_response)
                cb_wf new SAMLError("SAML Response was not success!", { status: get_status(saml_response) })
              response.type = 'authn_response'
              parse_authn_response saml_response, @private_key, identity_provider.certificates, cb_wf
            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'LogoutResponse').length is 1
              unless check_status_success(saml_response)
                cb_wf new SAMLError("SAML Response was not success!", { status: get_status(saml_response) })
              response.type = 'logout_response'
              setImmediate cb_wf, null, {}
            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'LogoutRequest').length is 1
              response.type = 'logout_request'
              setImmediate cb_wf, null, parse_logout_request saml_response
        (result, cb_wf) ->
          _.extend response, result
          cb_wf null, response
      ], cb

    # -- Optional
    # Returns a redirect URL, at which a user is logged out.
    create_logout_url: (identity_provider, name_id, session_index, relay_state..., cb) =>
      relay_state = relay_state[0]
      xml = create_logout_request @issuer, name_id, session_index, identity_provider.sso_logout_url
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        uri = url.parse identity_provider.sso_logout_url
        uri.query = sign_get_request deflated.toString('base64'), @private_key, relay_state
        cb null, url.format(uri)

    # Returns a redirect URL to confirm a successful logout.
    create_logout_response_url: (in_response_to, logout_url, cb) ->
      xml = create_logout_response @issuer, in_response_to, logout_url
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        uri = url.parse logout_url
        uri.query = sign_get_request deflated.toString('base64'), @private_key, undefined, true
        cb null, url.format(uri)

    # Returns XML metadata, used during initial SAML configuration
    create_metadata: (assert_endpoint) =>
      create_metadata @issuer, assert_endpoint, @certificate, @certificate

module.exports.IdentityProvider =
  class IdentityProvider
    constructor: (@sso_login_url, @sso_logout_url, @certificates) ->
      @certificates = [ @certificates ] unless _.isArray(@certificates)

if process.env.NODE_ENV is "test"
  module.exports.create_authn_request = create_authn_request
  module.exports.create_metadata = create_metadata
  module.exports.format_pem = format_pem
  module.exports.sign_get_request = sign_get_request
  module.exports.check_saml_signature = check_saml_signature
  module.exports.check_status_success = check_status_success
  module.exports.decrypt_assertion = decrypt_assertion
  module.exports.parse_response_header = parse_response_header
  module.exports.parse_logout_request = parse_logout_request
  module.exports.parse_assertion_attributes = parse_assertion_attributes
  module.exports.get_name_id = get_name_id
  module.exports.get_session_index = get_session_index
  module.exports.pretty_assertion_attributes = pretty_assertion_attributes
