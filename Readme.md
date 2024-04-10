# OpenID Connect Relying Party library for Rust

This module aims to support typical use-cases around implementing a relying party using sane defaults:

* Verifier:
  * OIDC Discovery ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414))
  * Access token / ID token verification (locally, without IdP interaction via [JWKS](https://datatracker.ietf.org/doc/html/rfc7517)) ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068), with quirks to support [Keycloak](https://github.com/keycloak/keycloak/discussions/8646))
  * Token parsing
  * Automatic, periodic JWKS refresh for reliable, fast token verification
* Client:
  * Automatic refresh of access tokens
  * Retrieval of access tokens (with specific lifetime)
  * Start session by supplying refresh token
  * Authentication
    * Supplying a refresh token (obtain it yourself)
    * Direct Grant (for specific use cases, behind a feature gate)

## Motivation

We are aware that this is just another OAuth/OIDC lib in the rust ecosystem. The issue is that most libraries do support only parts of the feature set we need, so in our project, we had to use multiple libraries together. During review of other libraries, we did not found a single one, which supports all the features we need. As we alone have multiple project re-implementing it, we decided to just roll the dice and build this library. We are open-sourcing it in the hope it will be useful for someone else having similar requirements.

We do not aim to re-write the verification part of the tokens, but more to use other libraries (which we think have good enough code quality) to provide a unified, simple interfaces or a relying party in Rust.

## License

MIT or Apache License version 2.0 at your will.
