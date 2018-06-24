'use strict';

const authenticators = require('./source/authenticators');

module.exports.OAuthServer = require('./source/OAuthServer');
module.exports.OAuthError = require('./source/OAuthError');

module.exports.AuthorizationCodeAuthenticator = authenticators.AuthorizationCodeAuthenticator;
module.exports.ClientCredentialsAuthenticator = authenticators.ClientCredentialsAuthenticator;
module.exports.PasswordAuthenticator = authenticators.PasswordAuthenticator;
