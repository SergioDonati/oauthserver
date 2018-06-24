
const request = require('supertest');
const should = require('should');
const express = require('express');
const {OAuthServer, OAuthError, AuthorizationCodeAuthenticator, ClientCredentialsAuthenticator} = require('./..');

const CLIENT_ID = '1111';
const CLIENT_SECRET = '******';
// assume that code will just sent
const AUTHORIZATION_CODE = 'VALID_CODE';

describe('TEST AuthorizationCodeAuthenticator', function(){
	this.timeout(30000);

	const app = express();
	const oauthserver = new OAuthServer();

	oauthserver.setGenerateTokenMethod(async (params, {grant_type}) =>{
		const expires_date = new Date();
		expires_date.setDate(expires_date.getDate() + 3); // 3 day
		if(grant_type=='authorization_code'){
			return {
				access_token: 'token:'+params.username,
				expires_in: (expires_date.getTime() - (new Date()).getTime()) / 1000,
				refresh_token: 'refreshtoken:'+params.username
			};
		}else if(grant_type=='client_credentials'){
			return {
				access_token: 'apptoken:'+params.clientId,
				token_type: 'Basic',
				expires_in: (expires_date.getTime() - (new Date()).getTime()) / 1000
			};
		}
	});

	oauthserver.setCheckAccessTokenMethod(async (req, token, params)=>{
		if (/token\:(.)+/.test(token)) return; //success
		else throw new OAuthError('access_denied');
	});

	oauthserver.setCheckRefreshTokenMethod(async (req, token)=>{
		if (/refreshtoken\:(.)+/.test(token)) return {username:'refreshed_admin'}; //success
		else throw new OAuthError('invalid_grant');
	});

	oauthserver.addAuthenticator('client_credentials', new ClientCredentialsAuthenticator({}, async(clientId, clientSecret)=>{
		if (clientId === CLIENT_ID && clientSecret === CLIENT_SECRET) return {clientId: CLIENT_ID};
		else throw new OAuthError('invalid_client');
	}));

	oauthserver.addAuthenticator('authorization_code', new AuthorizationCodeAuthenticator({}, async(code, redirectURI)=>{
		if (code === AUTHORIZATION_CODE) return true;
		else throw new OAuthError('invalid_grant');
	}));

	oauthserver.setVerifyClientMethod(async (req, {grant_type})=>{
		if(grant_type !== 'authorization_code') return true;
		if(!req.get('Authorization')) throw new OAuthError('invalid_client');

		const parts = req.get('Authorization').split(' ');
		if (parts.length != 2) throw new OAuthError('invalid_client');
		const scheme = parts[0];
		const credentials = parts[1];
		if (/^Basic$/i.test(scheme)) token = credentials;
		if (/apptoken\:(.)+/.test(token)) return {clientId: CLIENT_ID};
		else throw new OAuthError('invalid_client');
	});

	//The input getter for express request object
	oauthserver.setGetRequestInputMethod((requestContext, inputName) => {
		return requestContext.method === 'POST' ? requestContext.body[inputName] : requestContext.query[inputName];
	});

	//The header getter for express request object
	oauthserver.setGetRequestHeaderMethod((requestContext, headerName) => {
		return requestContext.get(headerName);
	});

	function authenticateMiddleware(req, res, next){
		oauthserver.authenticate(req).then(result => {
			res.set('Cache-Control', 'no-store');
			res.set('Pragma', 'no-cache');
			// pass the authentication
			res.json(result);
		}).catch(next);
	}

	function authorizeMiddleware(req, res, next){
		oauthserver.authorize(req).then(() => {
			next();
		}).catch(next);
	}

	app.get('/token', authenticateMiddleware);
	app.get('/secure', authorizeMiddleware, function(req, res, next){
		res.json({success:true});
	});

	app.use((error, req, res, next) => {
		if (error instanceof OAuthError && error.status == 401 && oauthserver.getTokenType()){
			res.set('WWW-Authenticate', oauthserver.getTokenType());
		}
		res.status(error.status || 400).json(error.toJSONResponse());
	});

	const agent = request.agent(app);

	it('should return access_tokens and authorize access', function(done){
		agent.get('/token?grant_type=client_credentials&client_id='+CLIENT_ID+'&client_secret='+CLIENT_SECRET).expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Basic');
			agent.get('/token')
			.query({
				grant_type: 'authorization_code',
				client_id: CLIENT_ID,
				code: AUTHORIZATION_CODE,
				redirect_uri: 'myapp.com/token/callback'
			})
			.set('Authorization', 'Basic '+res.body.access_token)
			.expect(200).end(function(err, res){
				if (err) return done(err);
				should(res.body).have.property('access_token');
				should(res.body).have.property('token_type', 'Bearer');

				agent.get('/secure')
				.set('Authorization', 'Bearer '+res.body.access_token)
				.expect(200).end(done);
			});
		});
	});

	it('should access not authorized', function(done){
		agent.get('/secure').expect(401).end(function(err, res){
			if (err) return done(err);
			should(res.header).have.property('www-authenticate', 'Bearer');
			should(res.body).have.property('error', 'invalid_request');
			done();
		});
	});
})
