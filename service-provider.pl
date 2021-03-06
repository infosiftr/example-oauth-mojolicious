#!/usr/bin/perl -w
use strict;
use warnings;
use feature ':5.12';
use sort 'stable';

use Mojolicious::Lite;
use Net::OAuth;
use MongoDB; # for token and nonce storage
use Tie::IxHash;

$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;

my $listen = shift || 'http://*:3000';

my %consumers = (
	# key => secret
	asdf => 'jkl;',
);

if (@ARGV > 1) {
	my $consumerKey = shift;
	my $consumerSecret = shift;
	%consumers = (
		$consumerKey => $consumerSecret,
	);
}

my $database = shift || 'example-oauth-mojolicious';

helper db => sub {
	my $self = shift;
	
	state $db = MongoDB::Connection->new(
		host => 'localhost',
		port => 27017,
	)->get_database($database);
	
	return $db;
};

helper handleRequest => sub {
	my $self = shift;
	my $type = shift;
	
	my %apiParams = (
		request_url => $self->req->url->clone->to_abs->query(undef)->fragment(undef),
		request_method => $self->req->method,
		consumer_secret => '', # DOH; required parameter for creation of certain request objects, but we don't (and can't) know the value until we know the consumer_key, which Net::OAuth parses out for us (and it would be silly to duplicate that parsing)
		token_secret => '', # DOH; same as consumer_secret
	);
	
	my $request = Net::OAuth->request($type);
	
	# work around issues with silly libraries adding a silly oauth_body_hash parameter that isn't in any final version of any of the specs
	$request->add_optional_message_params(qw( body_hash ));
	
	if (my $authHeader = $self->req->headers->authorization) {
		# if we have an Authorization header, that is ALWAYS the preferred method
		$request = $request->from_authorization_header($authHeader, %apiParams);
	}
	else {
		$request = $request->from_hash($self->req->params->to_hash, %apiParams);
	}
	
	unless ($consumers{$request->consumer_key}) {
		die 'unknown consumer';
	}
	
	$request->consumer_secret($consumers{$request->consumer_key});
	
	# if a token is provided and a token_secret is required, look up the secret from the database
	if ($request->{token} && grep { $_ eq 'token_secret' } @{ $request->required_api_params }, @{ $request->required_message_params }) {
		$request->token_secret(
			$self->db->oauthTokens->find_one({
					_id => $request->{token},
				}, { secret => 1 })->{secret}
		);
	}
	
	unless ($request->verify) {
		die 'invalid signature';
	}
	
	tie my %nonceId, 'Tie::IxHash'; # we have to use an IxHash here to ensure we have consistent ordering of fields for MongoDB, since {nonce: '...', timestamp: '...'} is a different key from {timestamp: '...', nonce: '...'}
	
	# I considered just making it a string and concatenating the two for simplicity, but that would've changed the semantics, since them anything that *concatentates* to the same nonce-timestamp value would be invalid, which isn't technically true
	
	$nonceId{nonce} = $request->nonce;
	$nonceId{timestamp} = $request->timestamp;
	
	unless ($self->db->oauthNonces->insert({
				_id => \%nonceId,
				providerTimestamp => time,
				token => $request->{token} || undef,
				consumerKey => $request->consumer_key,
			}, { safe => 1 })) {
		die 'invalid nonce/timestamp'; # already been used
	}
	
	if ($request->{token}) {
		# if this token is in the database, we should update it's lastUsedTimestamp value
		$self->db->oauthTokens->update({
				_id => $request->{token},
			}, {
				'$set' => {
					lastUsedTimestamp => time,
				},
			}, { safe => 1 });
	}
	
	return $request;
};

helper handleResponse => sub {
	my $self = shift;
	my $type = shift;
	my %apiParams = @_;
	
	my $response = Net::OAuth->response($type)->new(%apiParams);
	
	$self->res->headers->content_type('application/x-www-form-urlencoded');
	$self->render(data => $response->to_post_body);
};

helper generateRandomString => sub {
	# THIS IS NOT AT ALL SECURE!  USE A MORE SECURE SOURCE OF RANDOM DATA WHEN REALLY IMPLEMENTING OAUTH!
	
	my $self = shift;
	
	state $tokenChars = 'abcdefghjkmnpqrstuvwxyz23456789';
	
	my $ret = '';
	for (1 .. 32) { # longer tokens are also recommended
		$ret .= substr $tokenChars, int(rand(length $tokenChars)), 1;
	}
	
	return $ret;
};

get '/oauth/request_token' => sub {
	my $self = shift;
	
	my $request = $self->handleRequest('Request Token');
	
	my ($token, $secret);
	do {
		$token = $self->generateRandomString;
		$secret = $self->generateRandomString;
	} until (
		$self->db->oauthTokens->insert({
				_id => $token,
				secret => $secret,
				type => 'request',
				consumerKey => $request->consumer_key,
				createTimestamp => time,
				lastUsedTimestamp => 0,
				callback => $request->callback,
			}, { safe => 1 })
	);
	
	$self->handleResponse(
		'Request Token',
		token => $token,
		token_secret => $secret,
		callback_confirmed => 'true',
	);
};

get '/oauth/authorize' => sub {
	my $self = shift;
	
	my $requestToken = $self->db->oauthTokens->find_one({
			_id => $self->param('oauth_token'),
			type => 'request',
		}, {
			_id => 1,
			consumerKey => 1,
			callback => 1,
		});
	
	unless ($requestToken) {
		die 'invalid token';
	}
	
	# I only check this because I'm overly pedantic
	unless ($consumers{$requestToken->{consumerKey}}) {
		die 'invalid/revoked consumer';
	}
	
	# this is where a "login"/"authorize this application to view your data" page would be presented to the user - we'll just pretend that that happened and move on with the interesting stuff
	
	my $userId = 123; # yay, we're logged in ;)
	
	my $verifier = $self->generateRandomString;
	
	$self->db->oauthTokens->update({
			_id => $requestToken->{_id},
		}, {
			'$set' => {
				verifier => $verifier,
				userId => $userId,
			},
		}, {
			safe => 1,
		});
	
	if ($requestToken->{callback} eq 'oob') {
		$self->render(text => 'Verifier: ' . $verifier);
		return;
	}
	
	my $callback = Mojo::URL->new($requestToken->{callback});
	$callback->query->append(
		oauth_token => $requestToken->{_id},
		oauth_verifier => $verifier,
	);
	$self->redirect_to($callback);
};

get '/oauth/access_token' => sub {
	my $self = shift;
	
	my $request = $self->handleRequest('Access Token');
	
	my $requestToken = $self->db->oauthTokens->find_one({
			_id => $request->{token},
			type => 'request',
			consumerKey => $request->consumer_key,
			userId => { '$exists' => 1 },
		}, {
			userId => 1,
		});
	
	unless (
		$requestToken
		&& $self->db->oauthTokens->remove({
				_id => $requestToken->{_id},
			}, { safe => 1 })->{n} > 0
	) {
		die 'invalid token';
	}
	
	my $accessToken = $self->db->oauthTokens->find_one({
			type => 'access',
			consumerKey => $request->consumer_key,
			userId => $requestToken->{userId},
		}, {
			_id => 1,
			secret => 1,
		});
	
	my ($token, $secret);
	if ($accessToken) {
		$token = $accessToken->{_id};
		$secret = $accessToken->{secret};
	}
	else {
		do {
			$token = $self->generateRandomString;
			$secret = $self->generateRandomString;
		} until (
			$self->db->oauthTokens->insert({
					_id => $token,
					secret => $secret,
					type => 'access',
					consumerKey => $request->consumer_key,
					createTimestamp => time,
					lastUsedTimestamp => 0,
					userId => $requestToken->{userId},
				}, { safe => 1 })
		);
	}
	
	$self->handleResponse(
		'Access Token',
		token => $token,
		token_secret => $secret,
	);
};

get '/api/ping' => sub {
	my $self = shift;
	
	my $request = $self->handleRequest('Protected Resource');
	
	my $accessToken = $self->db->oauthTokens->find_one({
			_id => $request->{token},
			type => 'access',
			consumerKey => $request->consumer_key,
			userId => { '$exists' => 1 },
		}, {
			userId => 1,
		});
	
	$self->render(json => { userId => $accessToken->{userId}, pong => time });
};

app->start(qw(daemon -l), $listen);
