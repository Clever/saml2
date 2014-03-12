# SAML2 Library

## Description

Takes care of the complexities of the SAML protocol and provides an easy interface for using it. Specifically, creating metadata.xml files, creating `AuthnRequest`s and parsing and validating `AuthnResponse`s.

This is exposed as both a series of functions that implement each step of the SAML protocol, and an Express middleware that creates the necessary endpoints for the metadata, the login and the assertion.

## Pre-requisites

You'll need to create a private and public key.

```
TODO: Describe how
```

## Expected Usage

Include the SAML library.

```coffee
  saml_lib = require('saml')
```

To use the saml library, we think in terms of service providers (e.g. Clever) and identity providers (e.g. partners that use ADFS).

```coffee
  sp = saml_lib.service_provider
    private_key : 'saml.pem'
    certificate : 'saml.crt'

  idp = saml_lib.identity_provider
    sso_login_url : 'https://www.example.com/login'
    sso_logout_url : 'https://www.example.com/logout'
    certificate : 'adfs.crt'

```

Upon creating at least one service provider and one identity provider, you can then create SAML requests between them.

```coffee
  # -- REQUIRED --
  # Returns a redirect URL, at which a user can login
  sp.create_login_url(idp, cb)

  # Returns user object, if the login attempt was valid.
  sp.assert(idp, request_body, cb)

  # -- OPTIONAL --
  # Returns a redirect URL, at which a user is logged out.
  sp.create_logout_url(idp, cb)

  # Returns XML containing service-provider parameters.
  # For use during initial SAML configuration
  sp.create_metadata(idp, cb)
```

## Helper Methods

We will break each of the `service_provider` methods into minimal, testable methods.

```coffee
  ... TODO ...
  parse_xml
  parse_assert
  createAuthRequest
```

## Example: Express implementation using `saml-lib`

Library users will need to implement the URL endpoints. For example, express endpoints might look like the following:

```coffee
  app.get "/metadata.xml", (request, response) ->
    sp.get_metadata idp, (err, metadata) ->
      return response.send 500, err if err?
      response.send 200, metadata

  app.get "/login", (request, response) ->
    sp.create_login_url idp, (err, login_url) ->
      return response.send 500, err if err?
      response.location login_url
      response.send 302, "Redirecting..."

  app.get "/logout", (request, response) ->
    sp.create_logout_url idp, (err, login_url) ->
      return response.send 500, err if err?
      response.location login_url
      response.send 302, "Redirecting..."

  app.post "/assert", (request, response) ->
    sp.assert idp, response.body, (err, user) ->
      response.send 500, err if err?
      response.send 200, "Hello #{user.email}!"
```


## Related Libraries

- https://github.com/siphon-io/node-saml2
- https://github.com/bozzltron/express-saml
- https://github.com/bergie/passport-saml
- https://github.com/auth0/node-saml
- https://github.com/auth0/passport-wsfed-saml2

## Notes

remote_metadata: 'https://cleverad.ops.clever.com/FederationMetadata/2007-06/FederationMetadata.xml'
