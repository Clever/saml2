_             = require 'underscore'
{parseString} = require 'xml2js'
xmlbuilder    = require 'xmlbuilder'
xmlcrypto     = require 'xml-crypto'
xmldom        = require 'xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'


create_authn_request = ->
  xmlbuilder.create
    AuthnRequest:
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:protocol'
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
      '@Version': '2.0'
      '@ID': '_e23de96fdd91332b229368086adb655139e24ac6e2'
      '@IssueInstant': (new Date()).toISOString()
      #'@Destination': ''
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
check_saml_signature = (xml, cert_file) ->
  doc = (new xmldom.DOMParser()).parseFromString(xml)

  signature = xmlcrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
  sig = new xmlcrypto.SignedXml()
  sig.keyInfoProvider = new xmlcrypto.FileKeyInfo(cert_file)
  sig.loadSignature(signature.toString())
  sig.checkSignature(xml)

module.exports.ServiceProvider =
  class ServiceProvider
    constructor: (@private_key, @certificate) ->

    # -- Required
    # Returns a redirect URL, at which a user can login
    create_login_url: (identity_provider, cb) =>
      zlib.deflateRaw create_authn_request(), (err, deflated) =>
        cb err if err?
        cb null, "#{identity_provider.sso_login_url}?SAMLRequest=" + encodeURIComponent(deflated.toString('base64'))
        #loc = 'https://cleverad.ops.clever.com/adfs/ls/?SAMLRequest=' + encodeURIComponent(deflated.toString('base64')) + "&RelayState=https%3A%2F%2Fsaml.not.clever.com%2Fassert"

    # Returns user object, if the login attempt was valid.
    assert: (identity_provider, request_body, cb) ->
      # Base64 decode
      buf = new Buffer request_body.SAMLResponse, 'base64'
      # Decrypt
      saml_response = (new xmldom.DOMParser()).parseFromString buf.toString()
      encrypted_token = saml_response.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'EncryptedAssertion')[0]
      encrypted_data = encrypted_token.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0]

      xmlenc.decrypt encrypted_data.toString(), (key: @private_key), (err, decrypted_result) ->
        return cb err if err?
        return cb new Error("Error invalid signature!") unless check_saml_signature decrypted_result, "adfs.crt"

        parseString decrypted_result, (err, result) ->
          return cb err if err?
          # Parse it good
          if result['Assertion']?['AttributeStatement']?
            return cb null,
              _.chain(result['Assertion']['AttributeStatement'][0]['Attribute'])
              .map (attr) -> [attr['$']['Name'], attr['AttributeValue']]
              .object()
              .value()
          cb null, user

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
