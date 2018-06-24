'use strict';

const OAuthError = require('./../OAuthError');

const param1 = Symbol();
const param2 = Symbol();
const passReqSymbol = Symbol();
const verifyMethodSymbol = Symbol();

/**
 *	Implement Authorization Code Grant
 *	grant_type should be 'authorization_code'
 * 	@see https://tools.ietf.org/html/rfc6749#section-4.1
 *
 *	@param options
 *	@param verify the function that implement the busnes logic of the app for verify the activation code
 */
module.exports = class AuthorizationCodeAuthenticator{

	constructor({ codeField = 'code', redirectURIField = 'redirect_uri', passReq = false } = {}, verify){
		this[param1] = codeField;
		this[param2] = redirectURIField;
		this[passReqSymbol] = passReq;
		if (typeof verify !== 'function') throw new Error('you MUST provide a valid verify function.');
		this[verifyMethodSymbol] = verify;
	}

	async authenticate(requestContext, oauthserver){
		const code = oauthserver.getRequestInput(requestContext, this[param1]);
		const redirectURI = oauthserver.getRequestInput(requestContext, this[param2]);

		if (!code || !redirectURI) throw new OAuthError(OAuthError.ERROR_CODES.INVALID_GRANT);

		if (this[passReqSymbol]) return await this[verifyMethodSymbol](requestContext, code, redirectURI);
		else return await this[verifyMethodSymbol](code, redirectURI);
	}
}
