const _ = require('lodash');
const https = require('https');
const url = require('url');
const jwt = require('jsonwebtoken');
const fs = require('fs');
var util = require('util');
const queryString = require('query-string');
var passport = require('passport-strategy');

util.inherits(TokenValidatorStrategy, passport.Strategy);

var opts = {};

function TokenValidatorStrategy(options, verify)
{
	passport.Strategy.call(this);
	opts = _.cloneDeep(options);
	this.name = 'tokenvalidator';
}

/**
 * Validate access tokens/refresh tokens and establish a user session accordingly.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [myOptions] Strategy-specific options.
 * @api public
 */
TokenValidatorStrategy.prototype.authenticate = function(req, myOptions) {

	var self = this;

//	let code = req.query.code;
	let authToken = req.headers['authorization'];
	if ((authToken != null) && (authToken != ""))
	{
		if (authToken.substring(0,6).toLocaleLowerCase() == "bearer")
		{
			authToken = authToken.slice(6).trim();
		}
	}

	let accessToken = req.cookies["x-access-token"];
	let refreshToken = req.cookies["x-refresh-token"];
	if (((accessToken == null) || (accessToken == "")) && ((authToken != null) || (authToken != ""))) accessToken = authToken;

	/* purposely don't process code */
//	if (code)
//	{
//		let p = new Promise((resolve, reject) => {
//
//			let postData = {
//				code: code,
//				client_id: opts.clientID,
//				client_secret: opts.clientSecret,
//				grant_type: "authorization_code",
//				redirect_uri: "https://localhost:10443/auth/sso/callback"
//			};
//
//			let postDataStr = queryString.stringify(postData);
//			opts.url = url.parse(opts.tokenURL);
//
//			let token = req.params.auth_token
//			let options = {
//				host: opts.url.hostname,
//				path: opts.url.pathname,
//				port: 443,
//				method: 'POST',
//				headers: {
//					"Content-Type": "application/x-www-form-urlencoded",
//					"Content-Length": postDataStr.length
//				}
//			};
//
//
//
//			let callback = function (response) {
//				let str = ''
//				response.on('data', function (chunk) {
//					str += chunk;
//				});
//
//				response.on('end', function () {
//					console.log(str);
//					str = JSON.parse(str);
//					console.log("access token: ", str.access_token);
//					console.log("refresh token: ", str.refresh_token);
//					self._loadCerts(opts.CACertPathList, opts.certBasePath);
//					_.forEach(self._certs, (cert) => {
//						try
//						{
//							console.log(jwt.verify(str.id_token, cert));
//						}
//						catch (exception)
//						{
//							console.log(exception);
//						}
//					})
//
//					//alg
//					//profile
////					res.send(str);
//				});
//			}
//
//			let request = https.request(options, callback);
//
//			request.on('error', function (error) {
//				console.log(error);
//			});
//
//			request.write(postDataStr);
//
//			request.end();
//
//		});
//
//		return p;
//		self.fail();
//	}
//	else
	if (accessToken)
	{
		self._checkAccessToken(accessToken)
				.then((data) => {
					if ((data.active == true) || (data.active == "true"))
					{
						let userObj = {
											"userid": data.sub,
											"expiration": data.exp,
											"access_token": accessToken
										};
						if (req.cookies["x-refresh-token"])
						{
							userObj.refresh_token = req.cookies["x-refresh-token"];
						}
						self.success({ "id": data.sub, "_json": userObj });
					}
					else if (refreshToken)
					{
						self._checkRefreshToken(refreshToken, req);
					}
				})
				.catch((error) => {
					console.log(error);
					self.fail();
				});
	}
	else if (refreshToken)
	{
		self._checkRefreshToken(refreshToken, req);
	}
	else
	{
		self.fail();
	}
};

TokenValidatorStrategy.prototype._checkRefreshToken = function(refreshToken, req)
{
	let self = this;

//	let p = new Promise((resolve, reject) => {

		let postData = {
			refresh_token: refreshToken,
			client_id: opts.clientID,
			client_secret: opts.clientSecret,
			grant_type: "refresh_token"
		};

		let postDataStr = queryString.stringify(postData);
		opts.url = url.parse(opts.tokenURL);

		let options = {
			host: opts.url.hostname,
			path: opts.url.pathname,
			port: 443,
			method: 'POST',
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"Content-Length": postDataStr.length
			}
		};

		let callback = function (response) {
			let str = '';
			response.on('data', function (chunk) {
				str += chunk;
			});

			response.on('end', function () {
//				console.log(str);
				try
				{
					str = JSON.parse(str);
				}
				catch (error)
				{
//					reject(error);
					self.fail();
					return;
				}

				if (str.error)
				{
					console.log("error: ", str.error);
					console.log("msg: ", str.error_description);
					self.fail();
//					reject(str);
				}
				else
				{
					self._checkAccessToken(str.access_token)
						.then((data) => {
							if ((data.active == true) || (data.active == "true"))
							{
								let userObj = {
													"userid": data.sub,
													"expiration": data.exp,
													"access_token": str.access_token,
													"refresh_token": str.refresh_token
												};
								req.res.cookie('x-access-token', str.access_token);
								req.res.cookie('x-refresh-token', str.refresh_token);
								self.success({ "id": data.sub, "_json": userObj });
//								resolve(userObj);
							}
							else
							{
								console.log(data);
								self.fail();
//								reject(data);
							}
						})
						.catch((error) => {
							console.log(error);
							self.fail();
//							reject(error);
						});

				}
			});
		};

		let request = https.request(options, callback);

		request.on('error', function (error) {
			console.log(error);
			self.fail();
//			reject(error);
		});

		request.write(postDataStr);

		request.end();

//	});

//	return p;
}

TokenValidatorStrategy.prototype._checkAccessToken = function(accessToken)
{
	let p = new Promise((resolve, reject) => {

			let postData = {
				token: accessToken,
				client_id: opts.clientID,
				client_secret: opts.clientSecret
			};

			let postDataStr = queryString.stringify(postData);
			opts.url = url.parse(opts.introspectionURL);

			let options = {
				host: opts.url.hostname,
				path: opts.url.pathname,
				port: 443,
				method: 'POST',
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"Content-Length": postDataStr.length
				}
			};

			let callback = function (response) {
				let str = '';
				response.on('data', function (chunk) {
					str += chunk;
				});

				response.on('error', function (error) {
					console.log(error);
					reject(error);
				});

				response.on('end', function () {
					try
					{
						str = JSON.parse(str);
						resolve(str);
					}
					catch (error)
					{
						reject(error);
					}
				});
			}

			let request = https.request(options, callback);

			request.on('error', function (error) {
				console.log(error);
				reject(error);
			});

			request.write(postDataStr);

			request.end();
	});

	return p;
}

TokenValidatorStrategy.prototype._loadCerts = function(certPaths, certBasePath)
{
    this._certs = [];

    if (!certPaths)  throw new Error('Please include an array of the CA certs to be used.');
    if (!util.isArray(certPaths)) throw new Error('Please set the CA cert path list to be in an array format.');

    for(let i = 0; i < certPaths.length; i++) {
      let filepath = certBasePath + certPaths[i];

//      if(filepath[0] === '/')
//         var root = '/';
//      else
//         var root = '';
//
//      var pathlist = filepath.split(/\//g);
//      pathlist.unshift(root);
//
//      filepath = path.join.apply(null, pathlist);

      let content = fs.readFileSync(filepath);
      this._certs.push(content);
	}

	return;
}

exports = module.exports = TokenValidatorStrategy;

/**
 * Expose constructors.
 */
exports.TokenValidatorStrategy = TokenValidatorStrategy;
