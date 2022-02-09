# SAML2-js

[![CircleCI](https://circleci.com/gh/Clever/saml2/tree/master.svg?style=svg)](https://circleci.com/gh/Clever/saml2/tree/master)

`saml2-js` is a node module that abstracts away the complexities of the SAML protocol behind an easy to use interface.

## Usage

Install with [npm](https://www.npmjs.com/).

```bash
  npm install saml2-js --save
```

Include the SAML library.

```javascript
  var saml2 = require('saml2-js');
```

## Documentation

This library exports two constructors.

- [`ServiceProvider`](#ServiceProvider) - Represents a service provider that relies on a trusted [`IdentityProvider`](#IdentityProvider) for authentication and authorization in the SAML flow.
- [`IdentityProvider`](#IdentityProvider) - Represents an online service that authenticates users in the SAML flow.

<a name="note_options" />

**Note:**  Some options can be set on the [SP](#ServiceProvider), [IdP](#IdentityProvider), and/or on a per-method basis. For the options that are set in multiple places, they are overridden in the following order: per-method basis *overrides* [IdP](#IdentityProvider) which *overrides* [SP](#ServiceProvider).

<a name="ServiceProvider" />

### ServiceProvider(options)
Represents a service provider that relies on a trusted [`IdentityProvider`](#IdentityProvider) for authentication and authorization in the SAML flow.

#### Options
An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.

- `entity_id` - **Required** - Unique identifier for the service provider, often the URL of the metadata file.
- `private_key` - **Required** - (PEM format string) - Private key for the service provider.
- `certificate` - **Required** - (PEM format string) - Certificate for the service provider.
- `assert_endpoint` - **Required** - URL of service provider assert endpoint.
- `alt_private_keys` - (Array of PEM format strings) - Additional private keys to use when attempting to decrypt responses. Useful for adding backward-compatibility for old certificates after a rollover.
- `alt_certs` - (Array of PEM format strings) - Additional certificates to expose in the SAML metadata. Useful for staging new certificates for rollovers.
- `audience` - (String or RegExp) — If set, at least one of the `<Audience>` values within the `<AudienceRestriction>` condition of a SAML authentication response must match. Defaults to `entity_id`.
- `notbefore_skew` - (Number) – To account for clock skew between IdP and SP, accept responses with a NotBefore condition ahead of the current time (according to our clock) by this number of seconds. Defaults to 1. Set it to 0 for optimum security but no tolerance for clock skew.
- `force_authn` - (Boolean) - If true, forces re-authentication of users even if the user has a SSO session with the [IdP](#IdentityProvider).  This can also be configured on the [IdP](#IdentityProvider) or on a per-method basis.
- `auth_context` - Specifies `AuthnContextClassRef`.  This can also be configured on a per-method basis.
- `nameid_format` - Format for Name ID.  This can also be configured on a per-method basis.
- `sign_get_request` - (Boolean) - If true, signs the request.  This can also be configured on the [IdP](#IdentityProvider) or on a per-method basis.
- `allow_unencrypted_assertion` - (Boolean) - If true, allows unencrypted assertions.  This can also be configured on the [IdP](#IdentityProvider) or on a per-method basis.

#### Returns the following functions
- [`create_login_request_url(IdP, options, cb)`](#create_login_request_url) - Get a URL to initiate a login.
- [`redirect_assert(IdP, options, cb)`](#redirect_assert) - Gets a SAML response object if the login attempt is valid, used for redirect binding.
- [`post_assert(IdP, options, cb)`](#post_assert) - Gets a SAML response object if the login attempt is valid, used for post binding.
- [`create_logout_request_url(IdP, options, cb)`](#create_logout_request_url)- Creates a SAML Request URL to initiate a user logout.
- [`create_logout_response_url(IdP, options, cb)`](#create_logout_response_url) - Creates a SAML Response URL to confirm a successful [IdP](#IdentityProvider) initiated logout.
- [`create_metadata()`](#create_metadata) - Returns the XML metadata used during the initial SAML configuration.

#### Example
```javascript

  var sp_options = {
    entity_id: "https://sp.example.com/metadata.xml",
    private_key: fs.readFileSync("key-file.pem").toString(),
    certificate: fs.readFileSync("cert-file.crt").toString(),
    assert_endpoint: "https://sp.example.com/assert",
    force_authn: true,
    auth_context: { comparison: "exact", class_refs: ["urn:oasis:names:tc:SAML:1.0:am:password"] },
    nameid_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    sign_get_request: false,
    allow_unencrypted_assertion: true
  }

  // Call service provider constructor with options
  var sp = new saml2.ServiceProvider(sp_options);

  // Example use of service provider.
  // Call metadata to get XML metatadata used in configuration.
  var metadata = sp.create_metadata();

```

#### Service provider function definitions

<a name="create_login_request_url" />

##### create_login_request_url(IdP, options, cb)
Get a URL to initiate a login.

Takes the following arguments:
- `IdP` - [IdP](#IdentityProvider)
- `options` - An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.
  - `relay_state` - SAML relay state.
  - `auth_context` - Specifies `AuthnContextClassRef`.  This can also be configured on the [SP](#ServiceProvider).
  - `nameid_format` - Format for Name ID.  This can also be configured on the [SP](#ServiceProvider).
  - `force_authn`- (Boolean) - If true, forces re-authentication of users even if the user has a SSO session with the [IdP](#IdentityProvider).  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  - `sign_get_request` - (Boolean) - If true, signs the request.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
- `cb(error, login_url, request_id)` - Callback called with the login URL and ID of the request.


<a name="redirect_assert" />

##### redirect_assert(IdP, options, cb)
Gets a SAML response object if the login attempt is valid, used for redirect binding.

Takes the following arguments:
- `IdP` - [IdP](#IdentityProvider)
- `options` - An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.
  - `request_body` - (Object) - An object containing the parsed query string parameters.  This object should contain the value for either a `SAMLResponse` or `SAMLRequest`.
  - `allow_unencrypted_assertion` - (Boolean) - If true, allows unencrypted assertions.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  - `require_session_index` - (Boolean) - If false, allow the assertion to be valid without a `SessionIndex` attribute on the `AuthnStatement` node.
- `cb(error, response)` - Callback called with the [request response](#assert_response).

<a name="assert_response" />
Example of the SAML assert response returned:

  ```javascript
  { response_header:
     { id: '_abc-1',
       destination: 'https://sp.example.com/assert',
       in_response_to: '_abc-2' },
    type: 'authn_response',
    user:
     { name_id: 'nameid',
       session_index: '_abc-3',
       attributes:
        { 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': [ 'Test' ] } } }
  ```

<a name="post_assert" />

##### post_assert(IdP, options, cb)
Gets a SAML response object if the login attempt is valid, used for post binding.

Takes the following arguments:
- `IdP` - [IdP](#IdentityProvider)
- `options` - An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.
  - `request_body` - (Object) - An object containing the parsed query string parameters.  This object should contain the value for either a `SAMLResponse` or `SAMLRequest`.
  - `allow_unencrypted_assertion` - (Boolean) - If true, allows unencrypted assertions.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  - `require_session_index` - (Boolean) - If false, allow the assertion to be valid without a `SessionIndex` attribute on the `AuthnStatement` node.
  - `audience` - (String or RegExp) — If set, at least one of the `<Audience>` values within the `<AudienceRestriction>` condition of a SAML authentication response must match. Defaults to `entity_id`.
  - `notbefore_skew` - (Number) – To account for clock skew between IdP and SP, accept responses with a NotBefore condition ahead of the current time (according to our clock) by this number of seconds. Defaults to 1. Set it to 0 for optimum security but no tolerance for clock skew.
- `cb(error, response)` - Callback called with the [request response](#assert_response).


<a name="create_logout_request_url" />

##### create_logout_request_url(IdP, options, cb)
Creates a SAML Request URL to initiate a user logout.

Takes the following arguments:
- `IdP` - [IdP](#IdentityProvider).  Note: Can pass `sso_logout_url` instead of IdP.
- `options` - An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.
  + `name_id` - Format for Name ID.  This can also be configured on a per-method basis.
  + `session_index` - Session index to use for creating logout request.
  + `allow_unencrypted_assertion` - (Boolean) - If true, allows unencrypted assertions.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  + `sign_get_request` - (Boolean) - If true, signs the request.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  + `relay_state` - SAML relay state.
- `cb(error, request_url)` - Callback called with the logout request url.


<a name="create_logout_response_url" />

##### create_logout_response_url(IdP, options, cb)
Creates a SAML Response URL to confirm a successful [IdP](#IdentityProvider) initiated logout.

Takes the following arguments:
- `IdP` - [IdP](#IdentityProvider).  Note: Can pass `sso_logout_url` instead of IdP.
- `options` - An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.
  + `in_response_to` - The ID of the request that this is in response to. Should be checked against any sent request IDs.
  + `sign_get_request` - (Boolean) - If true, signs the request.  This can also be configured on the [IdP](#IdentityProvider) or [SP](#ServiceProvider).
  + `relay_state` - SAML relay state.
- `cb(error, response_url)` - Callback called with the logout response url.

<a name="create_metadata" />

##### create_metadata()
Returns the XML metadata used during the initial SAML configuration.

<a name="IdentityProvider" />

### IdentityProvider(options)
Represents an online service that authenticates users in the SAML flow.

Returns no functions, exists solely to be passed to an [SP](#ServiceProvider) function.

#### Options
An object that can contain the below options.  All options are strings, unless specified otherwise.  See [note](#note_options) for more information on options.

- `sso_login_url` - **Required** - Login url to use during a login request.
- `sso_logout_url` - **Required** - Logout url to use during a logout request.
- `certificates` - **Required** - (PEM format string or array of PEM format strings) - Certificate or certificates (array of certificate) for the identity provider.
- `force_authn` - (Boolean) - If true, forces re-authentication of users even if the user has a SSO session with the [IdP](#IdentityProvider).  This can also be configured on the [SP](#ServiceProvider) or on a per-method basis.
- `sign_get_request` - (Boolean) - If true, signs the request.  This can also be configured on the [[SP](#ServiceProvider) or on a per-method basis.
- `allow_unencrypted_assertion` - (Boolean) - If true, allows unencrypted assertions.  This can also be configured on the [SP](#ServiceProvider) or on a per-method basis.

#### Example
```javascript

  // Initialize options object
  var idp_options = {
    sso_login_url: "https://idp.example.com/login",
    sso_logout_url: "https://idp.example.com/logout",
    certificates: [fs.readFileSync("cert-file1.crt").toString(), fs.readFileSync("cert-file2.crt").toString()],
    force_authn: true,
    sign_get_request: false,
    allow_unencrypted_assertion: false
  };

  // Call identity provider constructor with options
  var idp = new saml2.IdentityProvider(idp_options);

  // Example usage of identity provider.
  // Pass identity provider into a service provider function with options and a callback.
  sp.post_assert(idp, {}, callback);

```


## Example: Express implementation

Library users will need to implement a set of URL endpoints, here is an example of [express](http://expressjs.com/) endpoints.

```javascript
var saml2 = require('saml2-js');
var fs = require('fs');
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({
  extended: true
}));

// Create service provider
var sp_options = {
  entity_id: "https://sp.example.com/metadata.xml",
  private_key: fs.readFileSync("key-file.pem").toString(),
  certificate: fs.readFileSync("cert-file.crt").toString(),
  assert_endpoint: "https://sp.example.com/assert"
};
var sp = new saml2.ServiceProvider(sp_options);

// Create identity provider
var idp_options = {
  sso_login_url: "https://idp.example.com/login",
  sso_logout_url: "https://idp.example.com/logout",
  certificates: [fs.readFileSync("cert-file1.crt").toString(), fs.readFileSync("cert-file2.crt").toString()]
};
var idp = new saml2.IdentityProvider(idp_options);

// ------ Define express endpoints ------

// Endpoint to retrieve metadata
app.get("/metadata.xml", function(req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});

// Starting point for login
app.get("/login", function(req, res) {
  sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
    if (err != null)
      return res.send(500);
    res.redirect(login_url);
  });
});

// Assert endpoint for when login completes
app.post("/assert", function(req, res) {
  var options = {request_body: req.body};
  sp.post_assert(idp, options, function(err, saml_response) {
    if (err != null)
      return res.send(500);

    // Save name_id and session_index for logout
    // Note:  In practice these should be saved in the user session, not globally.
    name_id = saml_response.user.name_id;
    session_index = saml_response.user.session_index;

    res.send("Hello #{saml_response.user.name_id}!");
  });
});

// Starting point for logout
app.get("/logout", function(req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };

  sp.create_logout_request_url(idp, options, function(err, logout_url) {
    if (err != null)
      return res.send(500);
    res.redirect(logout_url);
  });
});

app.listen(3000);

```
