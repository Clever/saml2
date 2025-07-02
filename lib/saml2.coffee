_             = require 'underscore'
async         = require 'async'
crypto        = require 'crypto'
debug         = require('debug') 'saml2'
url           = require 'url'
util          = require 'util'
xmlbuilder    = require 'xmlbuilder2'
xpath     = require 'xpath'
xmldom        = require '@xmldom/xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'
SignedXml     = require('xml-crypto').SignedXml

XMLNS =
  SAML: 'urn:oasis:names:tc:SAML:2.0:assertion'
  SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol'
  MD: 'urn:oasis:names:tc:SAML:2.0:metadata'
  DS: 'http://www.w3.org/2000/09/xmldsig#'
  XENC: 'http://www.w3.org/2001/04/xmlenc#'
  EXC_C14N: 'http://www.w3.org/2001/10/xml-exc-c14n#'

class SAMLError extends Error
  constructor: (@message, @extra) ->
    super @message

# Creates an AuthnRequest and returns it as a string of xml along with the randomly generated ID for the created
# request.
create_authn_request = (issuer, assert_endpoint, destination, force_authn, context, nameid_format) ->
  if context?
    context_element = { 'saml:AuthnContextClassRef': context.class_refs, '@Comparison': context.comparison }

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
        '@Format': nameid_format or 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        '@AllowCreate': 'true'
      RequestedAuthnContext: context_element
  .end()
  { id, xml }

# Adds an embedded signature to a previously generated AuthnRequest
sign_authn_request = (xml, private_key, options) ->
  signer = new SignedXml options
  signer.addReference({
    xpath: "//*[local-name(.)='AuthnRequest']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#']
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
  })
  signer.signingKey = private_key
  signer.computeSignature xml
  signer.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';


  return signer.getSignedXml()

# Creates metadata and returns it as a string of XML. The metadata has one POST assertion endpoint.
create_metadata = (entity_id, assert_endpoint, signing_certificates, encryption_certificates) ->
  signing_cert_descriptors = for signing_certificate in signing_certificates or []
    certificate_to_keyinfo('signing', signing_certificate)

  encryption_cert_descriptors = for encryption_certificate in encryption_certificates or []
    certificate_to_keyinfo('encryption', encryption_certificate)

  xmlbuilder.create
    'md:EntityDescriptor':
      '@xmlns:md': XMLNS.MD
      '@xmlns:ds': XMLNS.DS
      '@entityID': entity_id
      '@validUntil': (new Date(Date.now() + 1000 * 60 * 60)).toISOString()
      'md:SPSSODescriptor':
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol'
        'md:KeyDescriptor': signing_cert_descriptors.concat(encryption_cert_descriptors)
        'md:SingleLogoutService':
          '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          '@Location': assert_endpoint
        'md:AssertionConsumerService':
          '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
          '@Location': assert_endpoint
          '@index': '0'
  .end()

# Creates a LogoutRequest and returns it as a string of xml.
create_logout_request = (issuer, name_id, session_index, destination) ->
  id = '_' + crypto.randomBytes( 21 ).toString( 'hex' )
  xml = xmlbuilder.create
    'samlp:LogoutRequest':
      '@xmlns:samlp': XMLNS.SAMLP
      '@xmlns:saml': XMLNS.SAML
      '@ID': id
      '@Version': '2.0'
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      'saml:Issuer': issuer
      'saml:NameID': name_id
      'samlp:SessionIndex': session_index
  .end()

  {id, xml}

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
sign_request = (saml_request, private_key, relay_state, response=false) ->
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

  samlQueryString = {}

  if response
    samlQueryString.SAMLResponse = saml_request
  else
    samlQueryString.SAMLRequest = saml_request

  if relay_state
    samlQueryString.RelayState = relay_state

  samlQueryString.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  samlQueryString.Signature = sign.sign(format_pem(private_key, 'PRIVATE KEY'), 'base64')

  samlQueryString

# Converts a pem certificate to a KeyInfo object for use with XML.
certificate_to_keyinfo = (use, certificate) ->
  {
    '@use': use
    'ds:KeyInfo':
      '@xmlns:ds': XMLNS.DS
      'ds:X509Data':
        'ds:X509Certificate': extract_certificate_data certificate
  }

# Returns the raw certificate data with all extraneous characters removed.
extract_certificate_data = (certificate) ->
  cert_data = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec certificate
  cert_data = if cert_data? then cert_data[1] else certificate
  throw new Error('Invalid Certificate') unless cert_data?

  return cert_data.replace(/[\r\n]/g, '')

# Takes in an xml @dom containing a SAML Status and returns true if at least one status is Success.
check_status_success = (dom) ->
  status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status')
  return false unless status.length is 1
  for status_code in status[0].childNodes or []
    if status_code.attributes?
      status = get_attribute_value status_code, 'Value'
      return status is 'urn:oasis:names:tc:SAML:2.0:status:Success'
  false

get_status = (dom) ->
  status_list = {}
  status = dom.getElementsByTagNameNS(XMLNS.SAMLP, 'Status')
  return status_list unless status.length is 1

  for status_code in status[0].childNodes or []
    if status_code.attributes?
      top_status = get_attribute_value status_code, 'Value'
      status_list[top_status] ?= []
    for sub_status_code in status_code.childNodes or []
      if sub_status_code?.attributes?
        status = get_attribute_value sub_status_code, 'Value'
        status_list[top_status].push status
  status_list

to_error = (err) ->
  return null unless err?
  return new Error(util.inspect err) unless err instanceof Error
  err

# Takes in an XML @dom of an object containing an EncryptedAssertion and attempts to decrypt it
# using the @private_keys in the given order.
#
# @cb will be called with an error if the decryption fails, or the EncryptedAssertion cannot be
# found. If successful, it will be called with the decrypted data as a string.
decrypt_assertion = (dom, private_keys, cb) ->
  # This is needed because xmlenc sometimes throws an exception, and sometimes calls the passed-in
  # callback.
  cb = _.wrap cb, (fn, err, args...) -> setTimeout (-> fn to_error(err), args...), 0

  try
    encrypted_assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'EncryptedAssertion')
    unless encrypted_assertion.length is 1
      return cb new Error("Expected 1 EncryptedAssertion; found #{encrypted_assertion.length}.")

    encrypted_data = encrypted_assertion[0].getElementsByTagNameNS(XMLNS.XENC, 'EncryptedData')
    unless encrypted_data.length is 1
      return cb new Error("Expected 1 EncryptedData inside EncryptedAssertion; found #{encrypted_data.length}.")

    encrypted_assertion = encrypted_assertion[0].toString()
    errors = []
    async.eachOfSeries private_keys, (private_key, index, cb_e) ->
      xmlenc.decrypt encrypted_assertion, {key: format_pem(private_key, 'PRIVATE KEY')}, (err, result) ->
        if err?
          errors.push new Error("Decrypt failed: #{util.inspect err}") if err?
          return cb_e()

        debug "Decryption successful with private key ##{index}."
        cb null, result
    , -> cb new Error("Failed to decrypt assertion with provided key(s): #{util.inspect errors}")
  catch err
    cb new Error("Decrypt failed: #{util.inspect err}")

# This checks the signature of a saml document and returns either array containing the signed data if valid, or null
# if the signature is invalid. Comparing the result against null is NOT sufficient for signature checks as it doesn't
# verify the signature is signing the important content, nor is it preventing the parsing of unsigned content.
check_saml_signature = (xml, certificate) ->
  doc = (new xmldom.DOMParser()).parseFromString(xml)

  # xpath failed to capture <ds:Signature> nodes of direct descendents of the root.
  # Call documentElement to explicitly start from the root element of the document.
  signature = xpath.select("./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc.documentElement)
  return null unless signature.length is 1
  sig = new SignedXml(
    {
      publicCert: format_pem(certificate, 'CERTIFICATE')
    }
  )
  # sig.keyInfoProvider = getKey: -> format_pem(certificate, 'CERTIFICATE')
  sig.loadSignature signature[0]
  try
    valid = sig.checkSignature xml
    if valid
      return get_signed_data(doc, sig)
    else
      return null
  catch e
    # temporary hack
    if (e.message.indexOf("invalid signature") != -1)
      return null; # returns null for incorrect signature
    else
      throw e; # throw back the error


# Gets the data that is actually signed according to xml-crypto. This function should mirror the way xml-crypto finds
# elements for security reasons.
# deprecate
get_signed_data = (doc, sig) ->
  return sig.getSignedReferences(); # use new API
# Takes in an xml @dom of an object containing a SAML Response and returns an object containing the Destination and
# InResponseTo attributes of the Response if present. It will throw an error if the Response is missing or does not
# appear to be valid.
parse_response_header = (dom) ->
  for response_type in ['Response', 'LogoutResponse', 'LogoutRequest']
    response = dom.getElementsByTagNameNS(XMLNS.SAMLP, response_type)
    break if response.length > 0
  throw new Error("Expected 1 Response; found #{response.length}") unless response.length is 1

  response_header = {
    version: get_attribute_value response[0], 'Version'
    destination: get_attribute_value response[0], 'Destination'
    in_response_to: get_attribute_value response[0], 'InResponseTo'
    id: get_attribute_value response[0], 'ID'
  }

  # If no version attribute is supplied, assume v2
  version = response_header.version or '2.0'
  throw new Error "Invalid SAML Version #{version}" unless version is "2.0"
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

get_attribute_value = (node, attributeName) ->
  attributes = node.attributes or []
  attribute = _.filter attributes, (attr) -> attr.name is attributeName
  attribute[0]?.value

# Takes in an xml @dom of an object containing a SAML Assertion and returns the SessionIndex. It will throw an error
# if there is no SessionIndex, no Assertion, or the Assertion does not appear to be valid. Optionally you can pass a
# second argument `false` making SessionIndex optional. Doing so returns `null` instead of throwing an Error if the
# SessionIndex attribute does not exist.
get_session_info = (dom, index_required=true) ->
  assertion = dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
  throw new Error("Expected 1 Assertion; found #{assertion.length}") unless assertion.length is 1

  authn_statement = assertion[0].getElementsByTagNameNS(XMLNS.SAML, 'AuthnStatement')
  throw new Error("Expected 1 AuthnStatement; found #{authn_statement.length}") unless authn_statement.length is 1

  info =
    index: get_attribute_value authn_statement[0], 'SessionIndex'
    not_on_or_after: get_attribute_value authn_statement[0], 'SessionNotOnOrAfter'

  if index_required and not info.index?
    throw new Error("SessionIndex not an attribute of AuthnStatement.")

  info

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
    attribute_name = get_attribute_value attribute, 'Name'
    throw new Error("Invalid attribute without name") unless attribute_name?
    attribute_values = attribute.getElementsByTagNameNS(XMLNS.SAML, 'AttributeValue')
    assertion_attributes[attribute_name] = _.map(attribute_values, (attribute_value) ->
      attribute_value.childNodes[0]?.data or '')
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

  _.chain(assertion_attributes)
    .pairs()
    .filter(([k, v]) -> (claim_map[k]? and v.length > 0))
    .map(([k, v]) -> [claim_map[k], v[0]])
    .object()
    .value()

# takes in an XML string, returns an XML string
# applies all inclusive namespaces for signature assertions onto assertion tag
# used as recommended workaround for xml-crypto library limitation with inclusive namespaces
# see https://github.com/yaronn/xml-crypto/issues/48#issuecomment-129705816
add_namespaces_to_child_assertions = (xml_string) ->
    doc = new xmldom.DOMParser().parseFromString xml_string

    response_elements = doc.getElementsByTagNameNS XMLNS.SAMLP, 'Response'
    return xml_string if response_elements.length isnt 1
    response_element = response_elements[0]

    assertion_elements = response_element.getElementsByTagNameNS XMLNS.SAML, 'Assertion'
    return xml_string if assertion_elements.length isnt 1
    assertion_element = assertion_elements[0]

    inclusive_namespaces = assertion_element.getElementsByTagNameNS(XMLNS.EXC_C14N, 'InclusiveNamespaces')[0]
    namespaces = if inclusive_namespaces and prefixList = inclusive_namespaces.getAttribute('PrefixList')?.trim()
      ("xmlns:#{ns}" for ns in prefixList.split(' '))
    else
      (attr.name for attr in response_element.attributes when attr.name.match /^xmlns:/)

    # add the namespaces that are present in response and missing in assertion.
    for ns in namespaces
      if response_element.getAttribute(ns) and !assertion_element.getAttribute(ns)
        new_attribute = doc.createAttribute ns
        new_attribute.value = response_element.getAttribute ns
        assertion_element.setAttributeNode new_attribute

    return new xmldom.XMLSerializer().serializeToString response_element

# Takes a DOM of a saml_response, private keys with which to attempt decryption and the
# certificate(s) of the identity provider that issued it and will return a user object containing
# the attributes or an error if keys are incorrect or the response is invalid.
parse_authn_response = (saml_response, sp_private_keys, idp_certificates, allow_unencrypted, ignore_signature, require_session_index, ignore_timing, notbefore_skew, sp_audience, cb) ->
  user = {}

  async.waterfall [
    (cb_wf) ->
      # Decrypt the assertion
      decrypt_assertion saml_response, sp_private_keys, (err, result) ->
        return cb_wf null, result unless err?
        return cb_wf err, result unless allow_unencrypted and err.message == "Expected 1 EncryptedAssertion; found 0."
        assertion = saml_response.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
        unless assertion.length is 1
          return cb_wf new Error("Expected 1 Assertion or 1 EncryptedAssertion; found #{assertion.length}")
        cb_wf null, assertion[0].toString()
    (result, cb_wf) ->
      # Validate the signature
      debug result
      if ignore_signature
        return cb_wf null, (new xmldom.DOMParser()).parseFromString(result)

      saml_response_str = saml_response.toString()
      for cert, i in idp_certificates or []
        try
          signed_data = check_saml_signature(result, cert) or check_saml_signature saml_response_str, cert
        catch ex
          return cb_wf new Error("SAML Assertion signature check failed! (Certificate \##{i+1} may be invalid. #{ex.message}")
        unless signed_data
          continue # Cert was not valid, try the next one

        for sd in signed_data
          signed_dom = (new xmldom.DOMParser()).parseFromString(sd)

          assertion = signed_dom.getElementsByTagNameNS(XMLNS.SAML, 'Assertion')
          if assertion.length is 1
            return cb_wf null, signed_dom

          encryptedAssertion = signed_dom.getElementsByTagNameNS(XMLNS.SAML, 'EncryptedAssertion')
          if encryptedAssertion.length is 1
            return decrypt_assertion saml_response, sp_private_keys, (err, result) ->
              return cb_wf null, (new xmldom.DOMParser()).parseFromString(result) unless err?
              return cb_wf err
        return cb_wf new Error("Signed data did not contain a SAML Assertion!")
      return cb_wf new Error("SAML Assertion signature check failed! (checked #{idp_certificates.length} certificate(s))")
    (decrypted_assertion, cb_wf) ->
      # Validate the assertion conditions
      conditions = decrypted_assertion.getElementsByTagNameNS(XMLNS.SAML, 'Conditions')[0]
      if conditions?
        if ignore_timing != true
          for attribute in conditions.attributes
            condition = attribute.name.toLowerCase()
            if condition == 'notbefore' and Date.parse(attribute.value) > Date.now() + (notbefore_skew * 1000)
              return cb_wf new SAMLError('SAML Response is not yet valid', {NotBefore: attribute.value})
            if condition == 'notonorafter' and Date.parse(attribute.value) <= Date.now()
              return cb_wf new SAMLError('SAML Response is no longer valid', {NotOnOrAfter: attribute.value})

        audience_restriction = conditions.getElementsByTagNameNS(XMLNS.SAML, 'AudienceRestriction')[0]
        audiences = audience_restriction?.getElementsByTagNameNS(XMLNS.SAML, 'Audience')
        if audiences?.length > 0
          validAudience = _.find audiences, (audience) ->
            audienceValue = audience.firstChild?.data?.trim()
            !_.isEmpty(audienceValue?.trim()) and (
              (_.isRegExp(sp_audience) and sp_audience.test(audienceValue)) or
              (_.isString(sp_audience) and sp_audience.toLowerCase() == audienceValue.toLowerCase())
            )
          if !validAudience?
            return cb_wf new SAMLError('SAML Response is not valid for this audience')
      return cb_wf null, decrypted_assertion
    (validated_assertion, cb_wf) ->
      # Populate attributes
      try
        session_info = get_session_info validated_assertion, require_session_index
        user.name_id = get_name_id validated_assertion
        user.session_index = session_info.index
        if session_info.not_on_or_after?
          user.session_not_on_or_after = session_info.not_on_or_after

        assertion_attributes = parse_assertion_attributes validated_assertion
        user = _.extend user, pretty_assertion_attributes(assertion_attributes)
        user = _.extend user, attributes: assertion_attributes
        cb_wf null, { user }
      catch err
        return cb_wf err
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

set_option_defaults = (request_options, idp_options, sp_options) ->
  _.defaults({}, request_options, idp_options, sp_options)

module.exports.ServiceProvider =
  class ServiceProvider
    # Initializes a service provider given the passed options.
    #
    # @entity_id, @private_key, @assert_endpoint, @certificate, @alt_private_keys, @alt_certs can
    # only be set here and are used by exported functions.
    #
    # Rest of options can be set/overwritten by the identity provider and/or at function call.
    constructor: (options) ->
      {@entity_id, @private_key, @certificate, @assert_endpoint, @alt_private_keys, @alt_certs} = options

      options.audience ?= @entity_id
      options.notbefore_skew ?= 1

      @alt_private_keys = [].concat(@alt_private_keys or [])
      @alt_certs = [].concat(@alt_certs or [])

      @shared_options = _.pick(options,
        "force_authn", "auth_context", "nameid_format", "sign_get_request", "allow_unencrypted_assertion", "audience", "notbefore_skew")

    # Returns:
    #   Redirect URL at which a user can login
    #   ID of the request
    # Params:
    #   identity_provider
    #   options
    #   cb
    create_login_request_url: (identity_provider, options, cb) ->
      options = set_option_defaults options, identity_provider.shared_options, @shared_options

      { id, xml } = create_authn_request @entity_id, @assert_endpoint, identity_provider.sso_login_url, options.force_authn, options.auth_context, options.nameid_format
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        try
          uri = url.parse identity_provider.sso_login_url, true
        catch ex
          return cb ex
        delete uri.search # If you provide search and query search overrides query :/
        if options.sign_get_request
          _.extend(uri.query, sign_request(deflated.toString('base64'), @private_key, options.relay_state))
        else
          uri.query.SAMLRequest = deflated.toString 'base64'
          uri.query.RelayState = options.relay_state if options.relay_state?
        cb null, url.format(uri), id

    # Returns:
    #   An xml string with an AuthnRequest with an embedded xml signature
    # Params:
    #   identity_provider
    #   options
    create_authn_request_xml: (identity_provider, options) ->
      options = set_option_defaults options, identity_provider.shared_options, @shared_options

      { id, xml } = create_authn_request @entity_id, @assert_endpoint, identity_provider.sso_login_url, options.force_authn, options.auth_context, options.nameid_format
      return sign_authn_request(xml, @private_key, options)

    # Returns:
    #   An object containing the parsed response for a redirect assert.
    #   This type of assert inflates the response before parsing it.
    # Params:
    #   identity_provider
    #   options
    #   cb
    redirect_assert: (identity_provider, options, cb) ->
      options = _.defaults(_.extend(options, {get_request: true}), {require_session_index: true})
      options = set_option_defaults options, identity_provider.shared_options, @shared_options
      @_assert identity_provider, options, cb

    # Returns:
    #   An object containing the parsed response for a post assert.
    # Params:
    #   identity_provider
    #   options
    #   cb
    post_assert: (identity_provider, options, cb) ->
      options = _.defaults(_.extend(options, {get_request: false}), {require_session_index: true})
      options = set_option_defaults options, identity_provider.shared_options, @shared_options
      @_assert identity_provider, options, cb

    # Private function, called by redirect and post assert to return a response to
    # corresponding assert.
    _assert: (identity_provider, options, cb) ->
      unless options.request_body?.SAMLResponse? or options.request_body?.SAMLRequest?
        return setImmediate cb, new Error("Request body does not contain SAMLResponse or SAMLRequest.")

      unless _.isNumber(options.notbefore_skew)
        return setImmediate cb, new Error("Configuration error: `notbefore_skew` must be a number")

      saml_response = null
      response = {}

      async.waterfall [
        (cb_wf) ->
          raw = Buffer.from(options.request_body.SAMLResponse or options.request_body.SAMLRequest, 'base64')

          # Inflate response for redirect requests before parsing it.
          if (options.get_request)
            return zlib.inflateRaw raw, cb_wf
          setImmediate cb_wf, null, raw

        (response_buffer, cb_wf) =>
          debug saml_response
          saml_response_abnormalized = add_namespaces_to_child_assertions(response_buffer.toString())
          saml_response = (new xmldom.DOMParser()).parseFromString(saml_response_abnormalized)

          try
            response = { response_header: parse_response_header(saml_response) }
          catch err
            return cb err
          switch
            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'Response').length is 1
              unless check_status_success(saml_response)
                return cb_wf new SAMLError("SAML Response was not success!", {status: get_status(saml_response)})

              response.type = 'authn_response'

              parse_authn_response(
                saml_response,
                [@private_key].concat(@alt_private_keys),
                identity_provider.certificates,
                options.allow_unencrypted_assertion,
                options.ignore_signature,
                options.require_session_index,
                options.ignore_timing,
                options.notbefore_skew,
                options.audience
                cb_wf)

            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'LogoutResponse').length is 1
              unless check_status_success(saml_response)
                return cb_wf new SAMLError("SAML Response was not success!", {status: get_status(saml_response)})

              response.type = 'logout_response'
              setImmediate cb_wf, null, {}

            when saml_response.getElementsByTagNameNS(XMLNS.SAMLP, 'LogoutRequest').length is 1
              response.type = 'logout_request'
              setImmediate cb_wf, null, parse_logout_request saml_response

        (result, cb_wf) ->
          _.extend response, result
          cb_wf null, response
      ], cb

    # ----- Optional -----

    # Returns:
    #   Redirect URL, at which a user is logged out.
    # Params:
    #   identity_provider
    #   options
    #   cb
    create_logout_request_url: (identity_provider, options, cb) =>
      identity_provider = { sso_logout_url: identity_provider, options: {} } if _.isString(identity_provider)
      options = set_option_defaults options, identity_provider.shared_options, @shared_options
      {id, xml} = create_logout_request @entity_id, options.name_id, options.session_index, identity_provider.sso_logout_url
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        try
          uri = url.parse identity_provider.sso_logout_url, true
        catch ex
          return cb ex
        query = null
        if options.sign_get_request
          query = sign_request deflated.toString('base64'), @private_key, options.relay_state
        else
          query = SAMLRequest: deflated.toString 'base64'
          query.RelayState = options.relay_state if options.relay_state?
        uri.query = _.extend(query, uri.query)
        uri.search = null
        uri.query = query
        cb null, url.format(uri), id

    # Returns:
    #   Redirect URL to confirm a successful logout.
    # Params:
    #   identity_provider
    #   options
    #   cb
    create_logout_response_url: (identity_provider, options, cb) ->
      identity_provider = { sso_logout_url: identity_provider, options: {} } if _.isString(identity_provider)
      options = set_option_defaults options, identity_provider.shared_options, @shared_options

      xml = create_logout_response @entity_id, options.in_response_to, identity_provider.sso_logout_url
      zlib.deflateRaw xml, (err, deflated) =>
        return cb err if err?
        try
          uri = url.parse identity_provider.sso_logout_url
        catch ex
          return cb ex
        if options.sign_get_request
          uri.query = sign_request deflated.toString('base64'), @private_key, options.relay_state, true
        else
          uri.query = SAMLResponse: deflated.toString 'base64'
          uri.query.RelayState = options.relay_state if options.relay_state?
        cb null, url.format(uri)

    # Returns:
    #   XML metadata, used during initial SAML configuration
    create_metadata: =>
      certs = [@certificate].concat @alt_certs
      create_metadata @entity_id, @assert_endpoint, certs, certs

module.exports.IdentityProvider =
  class IdentityProvider
    constructor: (options) ->
      {@sso_login_url, @sso_logout_url, @certificates} = options
      @certificates = [ @certificates ] unless _.isArray(@certificates)
      @shared_options = _.pick(options, "force_authn", "sign_get_request", "allow_unencrypted_assertion")

if process.env.NODE_ENV is "test"
  module.exports.create_authn_request = create_authn_request
  module.exports.sign_authn_request = sign_authn_request
  module.exports.create_metadata = create_metadata
  module.exports.format_pem = format_pem
  module.exports.sign_request = sign_request
  module.exports.check_saml_signature = check_saml_signature
  module.exports.check_status_success = check_status_success
  module.exports.pretty_assertion_attributes = pretty_assertion_attributes
  module.exports.decrypt_assertion = decrypt_assertion
  module.exports.parse_response_header = parse_response_header
  module.exports.parse_logout_request = parse_logout_request
  module.exports.get_name_id = get_name_id
  module.exports.get_session_info = get_session_info
  module.exports.parse_assertion_attributes = parse_assertion_attributes
  module.exports.add_namespaces_to_child_assertions = add_namespaces_to_child_assertions
  module.exports.set_option_defaults = set_option_defaults
  module.exports.extract_certificate_data = extract_certificate_data
