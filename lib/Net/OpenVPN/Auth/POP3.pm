# Copyright (c) 2006, Branko F. Gracnar
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# + Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
#
# + Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
# + Neither the name of the Brane F. Gracnar nor the names of its contributors
#   may be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
package Net::OpenVPN::Auth::POP3;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use IO::Socket;
use Log::Log4perl;

=head1 NAME POP3

POP3 server backend authentication module 

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<host> (string, "localhost") POP3 server hostname

B<port> (integer, 110) POP3 server listening port

B<tls> (boolean, 0) Enable TLS/SSLv3 transport security. This option requires IO::Socket::SSL module

B<tls_version> (string, "tlsv1") Transport protocol type. Valid values: B<tlsv1, sslv2, sslv3>

B<tls_ciphers> (string, "HIGH") See IO::Socket::SSL

B<tls_cert_file> (string, undef) Certificate file

B<tls_key_file> (string, undef) Certificate key file

B<tls_ca_file> (string, undef) CA certificate file

B<tls_ca_path> (string, undef) CA authority directory

B<tls_verify> (hex integer, 0x00) See perldoc IO::Socket::SSL

B<timeout> (integer, 2) Timeout for socket operations

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = $class->SUPER::new(@_);

	##################################################
	#               PUBLIC VARS                      #
	##################################################

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_name} = "POP3";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->_init();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my $self = shift;
	$self->SUPER::clearParams();

	$self->{host} = "localhost";
	$self->{port} = 110;
	$self->{timeout} = 2;
	
	$self->{tls} = 0;
	$self->{tls_version} = "tlsv1";
	$self->{tls_ciphers} = "HIGH";
	$self->{tls_cert_file} = undef; 
	$self->{tls_key_file} =  undef;
	$self->{tls_ca_file} = undef;
	$self->{tls_ca_path} = undef;
	$self->{tls_verify} = 0x00;

	$self->{_pop} = undef;
	$self->{_has_ssl} = 0;

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	
	# connect to server
	return 0 unless ($self->_connect());

	# send username
	return 0 unless ($self->_popCmd("USER " . $struct->{username}));

	# send password
	return 0 unless ($self->_popCmd("PASS " . $struct->{password}));

	# close connection
	$self->_disconnect();

	return 1;
}


sub _init {
	my ($self) = @_;
	# check for IO::Socket::SSL availability
	eval {
		require IO::Socket::SSL;
	};
	$self->{_has_ssl} = ($@) ? 0 : 1;

	return 1;
}

sub _connect {
	my ($self) = @_;
	my $sock = undef;
	
	if ($self->{tls} && ! $self->{_has_ssl}) {
		$self->{error} = "Unable to use SSL/TLS secured session: Module IO::Socket::SSL is not available.";
		$self->{_log}->error($self->{error});
		return 0;
	}
	
	if ($self->{tls} && lc(substr($self->{tls_version}, 0, 3)) eq 'ssl') {
		$self->{_log}->debug("Connecting to host: " . $self->{host} . ":" . $self->{port} . " using SSL.");
		$sock = IO::Socket::SSL->new(
			PeerAddr => $self->{host},
			PeerPort => $self->{port},
			Proto => "tcp",
			ReuseAddr => 1,
			Timeout => $self->{timeout},
			$self->_getTlsHash()
		);
	} else {
		$self->{_log}->debug("Connecting to host: " . $self->{host} . ":" . $self->{port} . ".");
		$sock = IO::Socket::INET->new(
			PeerAddr => $self->{host},
			PeerPort => $self->{port},
			Proto => "tcp",
			ReuseAddr => 1,
			Timeout => $self->{timeout}
		);
	}

	unless (defined $sock) {
		$self->{error} = "Unable to connect to server '" . $self->{host} . ":" . $self->{port} . "': $@";
		$self->{_log}->error($self->{error});
		return 0;
	}
	
	# read server greeting
	return 0 unless ($self->_readResponse($sock));
	
	# TLS anyone? Upgrade normal socket to SSL-one :)
	if ($self->{tls} && lc($self->{tls_version}) eq 'tlsv1') {
		# send starttls command
		return 0 unless ($self->_popCmd("STLS", $sock));

		# start TLS session
		$self->{_log}->debug("Starting TLS session on unsecured socket.");
		my $r = IO::Socket::SSL->start_SSL(
			$sock,
			$self->_getTlsHash()
		);

		unless ($r) {
			$self->{error} = "Unable to start TLS secured session: " . $sock->errstr();
			$self->{_log}->error($self->{error});
			return 0;
		}
		
		$self->{_log}->debug("Successfully started TLS secured session.");
	}
	$self->{_log}->debug("Successfully connected.");

	$self->{_pop} = $sock;
	return 1;
}

sub _disconnect {
	my ($self, $sock) = @_;
	$sock = $self->{_pop} unless (defined $sock);

	if ($sock->connected()) {
		$self->_popCmd("QUIT");
		$sock = undef;
	}

	return 1;
}

sub _popCmd {
	my ($self, $cmd, $sock) = @_;
	$sock = $self->{_pop} unless (defined $sock);

	unless (defined $sock && $sock->connected()) {
		$self->{error} = "Invalid socket.";
		$self->{_log}->error($self->{error});
		return 0;
	}

	$self->{_log}->debug("Sending POP3 command: $cmd");
	print $sock $cmd, "\r\n";
	return $self->_readResponse($sock); 
}

sub _readResponse {
	my ($self, $sock) = @_;
	$sock = $self->{_pop} unless (defined $sock);

	unless (defined $sock && $sock->connected()) {
		$self->{error} = "Invalid socket.";
		$self->{_log}->error($self->{error});
		return undef;
	}

	my $line = $sock->getline();

	unless (defined $line && length($line) > 0) {
		$self->{error} = "Unable to read response from POP3 server: $!";
		$self->{_log}->error($self->{error});
		return 0;
	}
	
	# rtrim line
	$line =~ s/\s+$//g;

	$self->{_log}->debug("POP3 server response message: '$line'.");

	if ($line =~ m/^([\+\-A-Z]+)\s*(.*)/i) {
		my $code = uc($1);
		return 1 if ($code eq '+OK');

		$self->{error} = "Negative response from POP3 server: $2";
		$self->{_log}->error($self->{error});
		return 0;
	} else {
		$self->{error} = "Invalid response from POP3 server.";
		$self->{_log}->error($self->{error});
		return 0;
	}
}

sub _getTlsHash {
	my ($self) = @_;

	my %h = (
		SSL_version => $self->{tls_version},
		SSL_chiper_list =>  $self->{tls_ciphers},
		SSL_use_cert => (defined $self->{tls_cert_file}) ? 1 : 0,
		SSL_cert_file => $self->{tls_cert_file},
		SSL_key_file => $self->{tls_key_file},
		SSL_ca_file => $self->{tls_ca_file},
		SSL_ca_path => $self->{tls_ca_path},
		SSL_verify_mode => $self->{tls_verify},
	);

	return %h;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<IO::Socket::SSL>

=cut

# This line is mandatory...
1;