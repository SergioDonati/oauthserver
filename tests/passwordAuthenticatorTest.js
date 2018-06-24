
const request = require('supertest');
const should = require('should');
const express = require('express');
const {OAuthServer, OAuthError, PasswordAuthenticator} = require('./..');

describe('TEST PasswordAuthenticator', function(){
	this.timeout(30000);

	const app = express();
	const oauthserver = new OAuthServer();

	oauthserver.setGenerateTokenMethod(async (params, {grant_type}) =>{
		const expires_date = new Date();
		expires_date.setDate(expires_date.getDate() + 3); // 3 day
		if(grant_type=='password' || grant_type == 'refresh_token'){
			return {
				access_token: 'token:'+params.username,
				expires_in: (expires_date.getTime() - (new Date()).getTime()) / 1000,
				refresh_token: 'refreshtoken:'+params.username
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

	oauthserver.addAuthenticator('password', new PasswordAuthenticator({}, async(username, password)=>{
		if (username == 'admin' && password == '1234') return {username:'admin'};
		else throw new OAuthError('invalid_grant');
	}));

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
		if (!(error instanceof OAuthError)) error = new OAuthError(error);
		if(error.status == 401 && oauthserver.getTokenType()){
			res.set('WWW-Authenticate', oauthserver.getTokenType());
		}
		res.status(error.status || 400).json(error.toJSONResponse());
	});

	const agent = request.agent(app);

	it('should return access_token', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			done();
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

	it('should access authorized', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/secure?access_token='+res.body.access_token).expect(200).end(done);
		});
	});

	it('should access authorized with Authorization Bearer header', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);
			should(res.body).have.property('access_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/secure').set('Authorization', 'Bearer '+res.body.access_token).expect(200).end(done);
		});
	});

	it('should refresh the token', function(done){
		agent.get('/token?grant_type=password&username=admin&password=1234').expect(200).end(function(err, res){
			if (err) return done(err);

			should(res.body).have.property('access_token');
			should(res.body).have.property('refresh_token');
			should(res.body).have.property('token_type', 'Bearer');
			agent.get('/token?grant_type=refresh_token&refresh_token='+res.body.refresh_token)
			.expect(200).end(function(err, res){
				if (err) return done(err);

				should(res.body).have.property('access_token');
				should(res.body).have.property('token_type', 'Bearer');
				done();
			});
		});
	});
})
