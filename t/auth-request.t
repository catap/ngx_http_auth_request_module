#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for auth request module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite proxy fastcgi auth_basic/)
	->plan(13);

$t->write_file_expand('nginx.conf', <<'EOF');

master_process off;
daemon         off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 444;
        }

        location /open {
            auth_request /auth-open;
        }
        location = /auth-open {
            return 204;
        }

        location /open-static {
            auth_request /auth-open-static;
        }
        location = /auth-open-static {
            # nothing, use static file
        }

        location /unauthorized {
            auth_request /auth-unauthorized;
        }
        location = /auth-unauthorized {
            return 401;
        }

        location /forbidden {
            auth_request /auth-forbidden;
        }
        location = /auth-forbidden {
            return 403;
        }

        location /error {
            auth_request /auth-error;
        }
        location = /auth-error {
            return 404;
        }

        location /proxy {
            auth_request /auth-proxy;
        }
        location = /auth-proxy {
            proxy_pass http://127.0.0.1:8080/auth-basic;
        }
        location = /auth-basic {
            auth_basic "restricted";
            auth_basic_user_file %%TESTDIR%%/htpasswd;
        }

        location /fastcgi {
            auth_request /auth-fastcgi;
        }
        location = /auth-fastcgi {
            fastcgi_pass 127.0.0.1:8081;
        }
    }
}

EOF

$t->write_file('htpasswd', 'user:zz1T8N4tWvmbE' . "\n");
$t->write_file('auth-basic', 'INVISIBLE');
$t->write_file('auth-open-static', 'INVISIBLE');
$t->run();

###############################################################################

pass('runs');

like(http_get('/open'), qr/ 404 /, 'auth open');
like(http_get('/unauthorized'), qr/ 401 /, 'auth unauthorized');
like(http_get('/forbidden'), qr/ 403 /, 'auth forbidden');
like(http_get('/error'), qr/ 500 /, 'auth error');

like(http_get('/open-static'), qr/ 404 /, 'auth open static');
unlike(http_get('/open-static'), qr/INVISIBLE/, 'auth static no content');

like(http_get('/proxy'), qr/ 401 /, 'proxy auth unauthorized');
like(http_get('/proxy'), qr/WWW-Authenticate: Basic realm="restricted"/,
	'proxy auth has www-authenticate');
like(http_get_auth('/proxy'), qr/ 404 /, 'proxy auth pass');
unlike(http_get_auth('/proxy'), qr/INVISIBLE/, 'proxy auth no content');

SKIP: {
	eval { require FCGI; };
	skip 'FCGI not installed', 2 if $@;

	$t->run_daemon(\&fastcgi_daemon);
	$t->waitforsocket('127.0.0.1:8081');

	like(http_get('/fastcgi'), qr/ 404 /, 'fastcgi auth open');
	unlike(http_get('/fastcgi'), qr/INVISIBLE/, 'fastcgi auth no content');
}

###############################################################################

sub http_get_auth {
        my ($url, %extra) = @_;
        return http(<<EOF, %extra);
GET $url HTTP/1.0
Host: localhost
Authorization: Basic dXNlcjpzZWNyZXQ=

EOF
}

###############################################################################

sub fastcgi_daemon {
	my $socket = FCGI::OpenSocket('127.0.0.1:8081', 5);
	my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV,
		$socket);

	while ($request->Accept() >= 0) {
		print <<EOF;
Content-Type: text/html

INVISIBLE
EOF
	}

	FCGI::CloseSocket($socket);
}

###############################################################################
