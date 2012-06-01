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

get '/oauth/request_token' => sub {
	my $self = shift;
	
	# TODO
};

get '/oauth/authorize' => sub {
	my $self = shift;
	
	# TODO
};

get '/oauth/access_token' => sub {
	my $self = shift;
	
	# TODO
};

get '/api/ping' => sub {
	my $self = shift;
	
	# TODO
	
	$self->render(json => { pong => time });
};

app->start(qw(daemon -l), $listen);
