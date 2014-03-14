_             = require 'underscore'
async         = require 'async'
{parseString} = require 'xml2js'
util          = require 'util'
xmlbuilder    = require 'xmlbuilder'
xmlcrypto     = require 'xml-crypto'
xmldom        = require 'xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'


create_authn_request = (issuer, destination) ->
  xmlbuilder.create
    AuthnRequest:
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:protocol'
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
      '@Version': '2.0'
      '@ID': '_e23de96fdd91332b229368086adb655139e24ac6e2'
      '@IssueInstant': (new Date()).toISOString()
      '@Destination': destination
      '@AssertionConsumerServiceURL': 'https://saml.not.clever.com/assert'
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
      'saml:Issuer': "https://saml.not.clever.com/metadata.xml"
      NameIDPolicy:
        '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        '@AllowCreate': 'true'
  .end({pretty: true})

# This function return true/false if an XML document is signed with the provided
# cert. This is NOT sufficient for signature checks as it doesn't verify the
# signature is signing the important content, nor is it preventing the parsing
# of unsigned content.
check_saml_signature = (xml, certificate, cb) ->
  doc = (new xmldom.DOMParser()).parseFromString(xml)

  signature = xmlcrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  sig = new xmlcrypto.SignedXml()
  sig.keyInfoProvider = getKey: -> certificate
  sig.loadSignature(signature.toString())
  return cb null if sig.checkSignature(xml)
  cb new Error("SAML Assertion signature check failed!")

check_status_success = (dom, cb) ->
  status = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Status')
  return cb new Error("No SAML status found!") unless status.length is 1
  for status_code in status[0].childNodes
    for attr in status_code.attributes
      return cb null if attr.name is 'Value' and attr.value is 'urn:oasis:names:tc:SAML:2.0:status:Success'
  return cb new Error("SAML status wasn't success!")

decrypt_assertion = (dom, private_key, cb) ->
  encrypted_assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'EncryptedAssertion')[0]
  encrypted_data = encrypted_assertion.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0]
  xmlenc.decrypt encrypted_data.toString(), (key: private_key), cb

parse_assertion_attributes = (dom, cb) ->
  assertion = dom.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')[0]
  attribute_statement = assertion.getElementsByTagName('AttributeStatement')[0]
  assertion_attributes = {}
  for attribute in attribute_statement.childNodes
    for attr in attribute.attributes
      if attr.name is 'Name'
        attribute_name = attr.value
    return cb new Error("Invalid attribute without name") unless attribute_name?
    assertion_attributes[attribute_name] = _(attribute.childNodes).map (attribute_value) -> attribute_value.childNodes[0].data
  cb null, assertion_attributes

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
    .filter ([k, v]) -> (claim_map[k]? and v.length > 0)
    .map ([k, v]) -> [claim_map[k], v[0]]
    .object()
    .value()

module.exports.ServiceProvider =
  class ServiceProvider
    constructor: (@issuer, @private_key, @certificate) ->

    # -- Required
    # Returns a redirect URL, at which a user can login
    create_login_url: (identity_provider, cb) =>
      zlib.deflateRaw create_authn_request(@issuer, identity_provider.sso_login_url), (err, deflated) ->
        cb err if err?
        cb null, "#{identity_provider.sso_login_url}?SAMLRequest=" + encodeURIComponent(deflated.toString('base64'))

    # Returns user object, if the login attempt was valid.
    assert: (identity_provider, request_body, cb) ->
      saml_response = (new xmldom.DOMParser()).parseFromString(new Buffer(request_body.SAMLResponse, 'base64').toString())
      decrypted_assertion = null

      async.waterfall [
        (cb_wf) -> check_status_success saml_response, cb_wf
        (cb_wf) => decrypt_assertion saml_response, @private_key, cb_wf
        (result, cb_wf) ->
          decrypted_assertion = (new xmldom.DOMParser()).parseFromString(result)
          check_saml_signature result, identity_provider.certificate, cb_wf
        (cb_wf) -> parse_assertion_attributes decrypted_assertion, cb_wf
        (assertion_attributes, cb_wf) -> cb_wf null, pretty_assertion_attributes assertion_attributes
      ], cb

    # -- Optional
    # Returns a redirect URL, at which a user is logged out.
    create_logout_url: (identity_provider, cb) ->
      return

    # Returns XML metadata, used during initial SAML configuration
    create_metadata: (identity_provider, cb) ->
      return

module.exports.IdentityProvider =
  class IdentityProvider
    constructor: (@sso_login_url, @sso_logout_url, @certificate) ->
