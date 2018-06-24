'use strict';

const OAuthError = require('./../OAuthError');

const param1 = Symbol();
const param2 = Symbol();
const passReqSymbol = Symbol();
const verifyMethodSymbol = Symbol();

/**
 *	Implement Client Credentials Grant
 *	This version make use of client_id and client_secred
 *	Other version can be defined
 *	grant_type should be 'client_credentials'
 * 	@see https://tools.ietf.org/html/rfc6749#section-4.4
 */
module.exports = class ClientCredentialsAuthenticator{

	constructor({ clientIdField = 'client_id', clientSecretField = 'client_secret', passReq = false } = {}, verify){
		this[param1] = clientIdField;
		this[param2] = clientSecretField;
		this[passReqSymbol] = passReq;
		if (typeof verify !== 'function') throw new Error('you MUST provide a valid verify function.');
		this[verifyMethodSymbol] = verify;
	}

	async authenticate(requestContext, oauthserver){
		const clientId = oauthserver.getRequestInput(requestContext, this[param1]);
		const clientSecret = oauthserver.getRequestInput(requestContext, this[param2]);

		if (!clientId || !clientSecret) throw new OAuthError(OAuthError.ERROR_CODES.INVALID_GRANT);

		if (this[passReqSymbol]) return await this[verifyMethodSymbol](requestContext, clientId, clientSecret);
		else return await this[verifyMethodSymbol](clientId, clientSecret);
	}
}
