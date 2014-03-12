describe 'saml', ->

  describe 'xml metadata', ->
    it 'is valid xml', (done) ->
      done()
    it 'contains expected fields', (done) ->
      done()

  # Login
  describe 'login url', ->
    it 'creates an AuthRequest that is base64 encoded and compressed', (done) ->
      done()
    it 'includes relay URL', (done) ->
      done()
    it 'is configured according to the identity provider', (done) ->
      done()

  # Auth Request, before it is compressed and base-64 encoded
  describe 'AuthRequest', ->
    it 'is valid xml', (done) ->
      done()
    it 'contains expected fields', (done) ->
      done()

  # Assert
  describe 'assert', ->
    it 'expects properly formatted XML', (done) ->
      done()
    it 'expects base64 encoded SAMLResponse', (done) ->
      done()
    it 'finds encrypted data in SAMLResponse', (done) ->
      done()
    it 'can decode encrypted data in SAMLResponse', (done) ->
      done()
    it 'fails to decode encrypted data with private key', (done) ->
      done()
    it 'returns claims and their values', (done) ->
      done()
    it 'errors if no claims are found', (done) ->
      done()
    it 'allows claims with single or multiple value(s)', (done) ->
      done()
    it 'does not verify the assertions session ID, by default', (done) ->
      done()
    it 'verifies the assertions session ID, if specified by user', (done) ->
      done()
    it 'verifies the documents signature', (done) ->
      done()

  describe 'check_signature', ->
    it 'verifies document is signed', (done) ->
      done()

    # Other tests that *strictly* enforce the signature. For example...
    # - checks that correct part of document is signed
    # - checks that correct part of document is signed with correct signature
