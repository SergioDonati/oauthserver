'use strict';

const OAuthError = require('./OAuthError');

const tokenTypeSymbol = Symbol();
const getTokenMethodSymbol = Symbol();
const authenticatorsSymbol = Symbol();
const authorizersSymbol = Symbol();
const generateTokenMethodSymbol = Symbol();
const checkAccessTokenMethodSymbol = Symbol();
const checkRefreshTokenMethodSymbol = Symbol();
const verifyClientMethodSymbol = Symbol();
const getRequestHeaderMethodSymbol = Symbol();
const getRequestInputMethodSymbol = Symbol();

/**
 * @see https://tools.ietf.org/html/rfc6750
 */
function getBearerToken(requestContext){
	let token = this.getRequestInput(requestContext, 'access_token');
	// Check Bearer Token in header
	const authorizationHeader = this.getRequestHeader(requestContext, 'Authorization');
	if (!token && typeof(authorizationHeader) === 'string'){
		const parts = authorizationHeader.split(' ');
		if (parts.length != 2) throw new OAuthError(AuthRouteError.ERROR_CODES.INVALID_TOKEN);
		const scheme = parts[0];
		const credentials = parts[1];
		if (/^Bearer$/i.test(scheme)) token = credentials;
	}
	return token;
}

/**
 *	@see https://tools.ietf.org/html/rfc6749
 */
module.exports = class AuthRoute{

	constructor(options={}){
		this[tokenTypeSymbol] = options.token_type || 'Bearer'; //default is bearer
		this[getTokenMethodSymbol] = options.getToken || getBearerToken.bind(this); // default function for get bearer token
		this[authenticatorsSymbol] = new Map();
		this[authorizersSymbol] = new Map();
		this[generateTokenMethodSymbol] = options.generateToken || (async () => { throw new Error('YOU MUST implement generateToken method.'); })
		this[checkAccessTokenMethodSymbol] = options.checkAccessToken || (async () => { throw new Error('YOU MUST implement checkToken method.'); })
		this[checkRefreshTokenMethodSymbol] = options.checkRefreshToken || (async () => { throw new Error('YOU MUST implement checkRefreshToken method.'); })
		this[verifyClientMethodSymbol] = options.verifyClient || (async () => { return true; })
		this[getRequestHeaderMethodSymbol] = options.getRequestHeader || (async () => { throw new Error('YOU MUST implement getRequestHeader method.'); });
		this[getRequestInputMethodSymbol] = options.getRequestInput || (async () => { throw new Error('YOU MUST implement getRequestInput method.'); })
	}

	setGetRequestHeaderMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(requestContext) where requestContext is the object passed to authorize and/or authenticate');
		this[getRequestHeaderMethodSymbol] = fun;
	}

	setGetRequestInputMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(requestContext) where requestContext is the object passed to authorize and/or authenticate');
		this[getRequestInputMethodSymbol] = fun;
	}

	// Developer must implement your logic
	setGenerateTokenMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(params) where params is the result of checkAccessToken or checkRefreshToken');
		this[generateTokenMethodSymbol] = fun;
	}

	/**
	 *	Developer must implement your logic
	 * 	The checkAccessToken can throw
	 * 		OAuthError('invalid_token') if access token was invalid
	 */
	setCheckAccessTokenMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(requestContext, token, token_type)');
		this[checkAccessTokenMethodSymbol] = fun;
	}

	/**
	 *	Developer must implement your logic
	 *	can be optional if refresh token is not used
	 *	The checkRefreshToken can throw
	 *		OAuthError('invalid_grant') if refresh token was invalid
	 */
	setCheckRefreshTokenMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(requestContext, token, token_type)');
		this[checkRefreshTokenMethodSymbol] = fun;
	}

	/**
	 * Developer must implement your logic
	 * The verifyClient can throw
	 * 		OAuthError('invalid_client') if access token was invalid
	 * a fail must also set the header WWW-Authenticate with the expected scheme used by client
	 * This function is optional, by default return true, you can define this function
	 * otherwise define your login directly in authenticate method of grant authenticator
	 * the difference is that verifyClient is called also for 'refresh_token' grant type
	 * while authenticate is called only if grant_type is equals to the specified authenitcator grant
	 */
	setVerifyClientMethod(fun){
		if(typeof fun !== 'function') throw new Error('first param MUST be a function(req, {grant_type})');
		this[verifyClientMethodSymbol] = fun;
	}

	getRequestHeader(requestContext, headerName){
		return this[getRequestHeaderMethodSymbol](requestContext, headerName);
	}

	getRequestInput(requestContext, inputName){
		return this[getRequestInputMethodSymbol](requestContext, inputName);
	}

	getTokenType(){
		return this[tokenTypeSymbol];
	}

	/**
	 * The authenticator is an object that has authenticate method
	 *	the authenticate function can throw
	 *		OAuthError('invalid_grant')
	 *		OAuthError('invalid_client')
	 *		OAuthError('invalid_request')
	 *  if authentication fail or something go wrong
	 * the grant_type 'refresh_token' not work cause is handled internally and call checkRefreshToken function
	 */
	addAuthenticator(grant_type, authenticator){
		if (!authenticator || typeof authenticator.authenticate !== 'function') throw new Error('Invalid authenticator, MUST implement authenticate(req) method.');
		this[authenticatorsSymbol].set(grant_type, authenticator);
	}

	/**
	 *	The authorizer function can throw
	 * 		OAuthError('access_denied') if authorization fail
	 */
	addAuthorizer(name, authorizer){
		if (typeof authorizer !== 'function') throw new Error('Invalid authorizer, MUST be a function(req, ...args)');
		this[authorizersSymbol].set(name, authorizer);
	}

	/**
	 *	Execute the authentication flow based on grant_type
	 */
	async authenticate(requestContext){
		const grant_type = this.getRequestInput(requestContext, 'grant_type');
		if (!grant_type) throw new OAuthError(OAuthError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);

		await this[verifyClientMethodSymbol](requestContext, {grant_type});

		let params = null;
		if(grant_type == 'refresh_token'){
			const refresh_token = this.getRequestInput(requestContext, 'refresh_token');
			params = await this[checkRefreshTokenMethodSymbol](requestContext, refresh_token);
		}else{
			if (!this[authenticatorsSymbol].has(grant_type)) throw new OAuthError(OAuthError.ERROR_CODES.UNSUPPORTED_GRANT_TYPE);
			params = await this[authenticatorsSymbol].get(grant_type).authenticate(requestContext, this);
		}
		const result = await this[generateTokenMethodSymbol](params, {grant_type, oauthserver: this});

		if(typeof(result) !== 'object') throw new OAuthError(OAuthError.ERROR_CODES.INVALID_GRANT);

		return {
			access_token: result.access_token,
			token_type: result.token_type || this[tokenTypeSymbol],
			expires_in: result.expires_in,
			refresh_token: result.refresh_token,
			scope: result.scope,
		};
	}

	/**
	 *	Check the authorization for the request
	 */
	async authorize(requestContext, name, ...args){
		const access_token = await this[getTokenMethodSymbol](requestContext);
		if (!access_token){
			throw new OAuthError(OAuthError.ERROR_CODES.INVALID_REQUEST, 401);
		}
		await this[checkAccessTokenMethodSymbol](requestContext, access_token, {token_type: this[tokenTypeSymbol]});

		if (!name) return; // not other check needs
		if (!this[authorizersSymbol].has(name)){
			console.warn('Called authorize method with param name: "%s", but none authorizer with this name was registered.', name);
			return;
		}
		const access = await this[authorizersSymbol].get(name)(requestContext, ...args);

		if(access !== true) throw new OAuthError(OAuthError.ERROR_CODES.ACCESS_DENIED, 401);

		return;
	}
}
