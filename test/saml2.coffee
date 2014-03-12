_             = require 'underscore'
{parseString} = require 'xml2js'
xmlbuilder    = require 'xmlbuilder'
xmlcrypto     = require 'xml-crypto'
xmldom        = require 'xmldom'
xmlenc        = require 'xml-encryption'
zlib          = require 'zlib'

assert = require 'assert'
describe 'saml', ->

  describe 'xml metadata', ->
    it 'is valid xml', (done) ->
      assert false
      done()
    it 'contains expected fields', (done) ->
      assert false
      done()

  # Login
  describe 'login url', ->
    it 'creates an AuthRequest that is base64 encoded and compressed', (done) ->
      assert false
      done()
    it 'includes relay URL', (done) ->
      assert false
      done()
    it 'is configured according to the identity provider', (done) ->
      assert false
      done()

  # Auth Request, before it is compressed and base-64 encoded
  describe 'AuthRequest', ->
    it 'is valid xml', (done) ->
      assert false
      done()
    it 'contains expected fields', (done) ->
      assert false
      done()

  # Assert
  describe 'assert', ->
    it 'expects properly formatted XML', (done) ->
      assert false
      done()
    it 'expects base64 encoded SAMLResponse', (done) ->
      assert false
      done()
    it 'finds encrypted data in SAMLResponse', (done) ->
      assert false
      done()
    it 'can decode encrypted data in SAMLResponse', (done) ->
      assert false
      done()
    it 'fails to decode encrypted data with private key', (done) ->
      assert false
      done()
    it 'returns claims and their values', (done) ->
      assert false
      done()
    it 'errors if no claims are found', (done) ->
      assert false
      done()
    it 'allows claims with single or multiple value(s)', (done) ->
      assert false
      done()
    it 'does not verify the assertions session ID, by default', (done) ->
      assert false
      done()
    it 'verifies the assertions session ID, if specified by user', (done) ->
      assert false
      done()
    it 'verifies the documents signature', (done) ->
      assert false
      done()

  describe 'check_signature', ->
    it 'verifies document is signed', (done) ->
      assert false
      done()

    # Other tests that *strictly* enforce the signature. For example...
    # - checks that correct part of document is signed
    # - checks that correct part of document is signed with correct signature
