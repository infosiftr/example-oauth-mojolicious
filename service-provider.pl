#!/usr/bin/perl -w
use strict;
use warnings;
use feature ':5.12';
use sort 'stable';

use Mojolicious::Lite;
use Net::OAuth;
use MongoDB; # for token and nonce storage

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

helper db => sub {
	my $self = shift;
	
	return MongoDB->new;
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
	
	# TODO check database to ensure nonce/timestamp combination is unique
	
	# if a token is provided and a token_secret is required, look up the secret from the database
	if ($request->{token} && grep { $_ eq 'token_secret' } @{ $request->required_api_params }, @{ $request->required_message_params }) {
		my $token = $request->{token};
		
		# TODO look up token_secret from the database
	}
	
	unless ($request->verify) {
		die 'invalid signature';
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
	
	my $token = $self->generateRandomString;
	my $secret = $self->generateRandomString;
	
	# TODO save token into database
	
	$self->handleResponse(
		'Request Token',
		token => $token,
		token_secret => $secret,
		callback_confirmed => 'true',
	);
};

get '/oauth/authorize' => sub {
	my $self = shift;
	
	# TODO
};

get '/oauth/access_token' => sub {
	my $self = shift;
	
	my $request = $self->handleRequest('Access Token');
	
	# TODO
};

get '/api/ping' => sub {
	my $self = shift;
	
	my $request = $self->handleRequest('Protected Resource');
	
	# TODO
	
	$self->render(json => { pong => time });
};

app->start(qw(daemon -l), $listen);
