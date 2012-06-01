var unixTimestamp = new Date().getTime() / 1000.0;

var oauthNonces = {
	_id: [ 'wIjqoS', '137131200' ], // nonce, consumerTimestamp
	providerTimestamp: unixTimestamp,
	token: 'hh5s93j4hdidpola',
	consumerKey: 'dpf43f3p2l4k3l03'
};

var oauthTokens = {
	_id: 'hh5s93j4hdidpola', // token
	secret: 'hdhd0244k9j7ao03',
	type: 'request', // or 'access'
	consumerKey: 'dpf43f3p2l4k3l03',
	createTimestamp: unixTimestamp,
	lastUsedTimestamp: unixTimestamp,
	
	// request only:
	verifier: 'hfdp7dh39dks9884',
	callback: 'http://printer.example.com/ready',
	
	// application specific data:
	userId: 123 // the ID of the user this token is attached to (if it's an access token or an authorized request token)
};
