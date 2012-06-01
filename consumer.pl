#!/usr/bin/perl -w
use strict;
use warnings;

use Mojolicious::Lite;
use Net::OAuth::Client;

$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;

my $listen = shift || 'http://*:3001';
my $serviceProviderBase = shift || 'http://localhost:3000';
my $consumerKey = shift || 'asdf';
my $consumerSecret = shift || 'jkl;';
my $apiEndpoint = shift || '/api/ping';

helper client => sub {
	my $self = shift;
	
	return Net::OAuth::Client->new(
		$consumerKey,
		$consumerSecret,
		site => $serviceProviderBase,
		callback => $self->url_for('/callback')->to_abs,
		debug => 1,
	);
};

get '/' => sub {
	my $self = shift;
	
	my $client = $self->client;
	
	$self->redirect_to($client->authorize_url);
};

get '/callback' => sub {
	my $self = shift;
	
	my $client = $self->client;
	
	my $access = $client->get_access_token($self->param('oauth_token'), $self->param('oauth_verifier'));
	
	$self->redirect_to($self->url_for('/access')->query(
			token => $access->token,
			secret => $access->token_secret,
		));
};

get '/access' => sub {
	my $self = shift;
	
	my $client = $self->client;
	my $access = Net::OAuth::AccessToken->new(
		client => $client,
		token => $self->param('token'),
		token_secret => $self->param('secret'),
	);
	
	my $response = $access->get('/oauth/get_user');
	
	if ($response->is_success) {
		$self->render(json => Mojo::JSON->decode($response->decoded_content));
	}
	else {
		$self->render(text => 'FAILURE');
	}
};

app->start(qw(daemon -l), $listen);
