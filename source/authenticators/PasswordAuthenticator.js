'use strict';

const OAuthError = require('./../OAuthError');

const param1 = Symbol();
const param2 = Symbol();
const passReqSymbol = Symbol();
const verifyMethodSymbol = Symbol();

/**
 *	Implement Resource Owner Password Credentials Grant
 *	grant_type should be 'password'
 *	@see https://tools.ietf.org/html/rfc6749#page-37
 */
module.exports = class PasswordAuthenticator{

	constructor({ usernameField = 'username', passwordField = 'password', passReq = false } = {}, verify){
		this[param1] = usernameField;
		this[param2] = passwordField;
		this[passReqSymbol] = passReq;
		if (typeof verify !== 'function') throw new Error('YOU must provide a valid verify function.');
		this[verifyMethodSymbol] = verify;
	}

	async authenticate(requestContext, oauthserver){
		const username = oauthserver.getRequestInput(requestContext, this[param1]);
		const password = oauthserver.getRequestInput(requestContext, this[param2]);

		if (!username || !password) throw new OAuthError(OAuthError.ERROR_CODES.INVALID_GRANT);

		if (this[passReqSymbol] === true) return await this[verifyMethodSymbol](requestContext, username, password);
		else return await this[verifyMethodSymbol](username, password);
	}
 }
