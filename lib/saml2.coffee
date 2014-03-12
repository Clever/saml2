module.exports = ->

  class ServiceProvider
    constructor: (private_key, certificate) ->

    # -- Required
    # Returns a redirect URL, at which a user can login
    create_login_url: (identity_provider, cb) ->
      return

    # Returns user object, if the login attempt was valid.
    assert: (identity_provider, request_body, cb) ->
      return

    # -- Optional
    # Returns a redirect URL, at which a user is logged out.
    create_logout_url: (identity_provider, cb) ->
      return

    # Returns XML metadata, used during initial SAML configuration
    create_metadata: (identity_provider, cb) ->
      return

  class IdentityProvider
    constructor: (sso_login_url, sso_logout_url, certificate) ->
