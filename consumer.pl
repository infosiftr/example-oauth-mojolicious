#!/usr/bin/perl -w
use strict;
use warnings;
use feature ':5.12';
use sort 'stable';

use Mojolicious::Lite;
use Net::OAuth::Client;

# TODO write and use a new Net::OAuth::MojoClient module that uses Mojo::UserAgent and accepts more options like whether to make the request use the Authorization header instead of query parameters

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
		session => sub {
			$self->session->{tokens} ||= {};
			
			if (@_ == 1) {
				return $self->session->{tokens}->{$_[0]};
			}
			
			while (@_) {
				my $key = shift;
				my $val = shift;
				
				$self->session->{tokens}->{$key} = $val;
			}
			
			return $self->session->{tokens};
		},
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
	
	my $response = $access->get($apiEndpoint);
	
	if ($response->is_success) {
		$self->render(json => Mojo::JSON->decode($response->decoded_content));
	}
	else {
		$self->render(text => 'FAILURE');
	}
};

app->start(qw(daemon -l), $listen);
