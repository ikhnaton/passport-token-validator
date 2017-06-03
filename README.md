## Token Validator Strategy

This is a token validation strategy for Passport.js.  This simply validates an access_token or refresh_token and once determined valid, creates a user session containing the userid and tokens.  Additionally, the access token and refresh tokens are set as cookies so that your front end can retrieve and store them for later use.  This strategy can be used when protecting resources on a resource server allowing authorization to be done externally.  You simply are validating that your authentication server says the tokens are valid for the user in question.

#### Cookies used:

- x-access-token
- x-refresh-token

#### Usage

Simply initialize the Strategy and provide your Oauth server information like shown to use:

```
var TokenValidatorStrategy = require('passport-token-validator').TokenValidatorStrategy;
	var Strategy = new TokenValidatorStrategy({
			authorizationURL: settings.authorization_url,
			tokenURL: settings.token_url,
			introspectionURL: settings.introspect_url,
			clientID: settings.client_id,
			scope: 'openid',
			response_type: 'code',
			clientSecret: settings.client_secret,
			callbackURL: settings.callback_url
		});
	passport.use(Strategy);
	```