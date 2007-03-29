# Copyright (c) 2006, Brane F. Gracnar
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
package Net::OpenVPN::AuthDaemon;

@ISA = qw (
	Net::Server::PreFork
);

use strict;
use warnings;

use Log::Log4perl;
use Net::Server::PreFork;
use File::Basename qw(basename);

use vars qw($MYNAME);

use Net::OpenVPN::AuthChain;

use constant MAXLINES => 20;
use constant MAX_LINE_LENGTH => 1024;

##################################################
#             OBJECT CONSTRUCTOR                 #
##################################################

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};

	##################################################
	#               PUBLIC VARS                      #
	##################################################
	$self->{auth_timeout} = 5;
	$self->{umask} = umask();

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);
	$self->{_myname} = "AuthDaemon";

	bless($self, $class);
	return $self;
};

##################################################
#              PUBLIC  METHODS                   #
##################################################

sub getError {
	my ($self) = @_;
	return $self->{error};
}

sub child_init_hook {
	my ($self) = @_;
	$0 = $self->{_myname} . " (worker, idle, virgin)";
	return 1;
}

sub post_bind_hook {
	my ($self) = @_;
	if (defined ($self->{umask})) {
		umask($self->{umask});
	}

	# relocate stdout, stderr
	tie *STDERR, $self;
	tie *STDOUT, $self;

	# close stdin and reopen it on null device
	close(STDIN);
	open(STDIN, File::Spec->devnull());
}

sub post_accept_hook {
	my ($self) = @_;
	my $host = "unix socket ";
	eval {
		$host = $self->{server}->{client}->peerhost();
	};

	$0 = $self->{_myname} . " (worker, connect from: " . $host . ": processing)";
	return 1;
}

sub pre_loop_hook {
	my ($self) = @_;
	$0 = $self->{_myname} . " (master)";
}

sub post_process_request_hook {
	my ($self) = @_;
	$0 = $self->{_myname} . " (worker, idle)";
}

sub process_request {
	my ($self) = @_;
	my $params = undef;
	my $result_str = "NO Invalid credentials.";
	
	# set up signal handler
	local $SIG{ALRM} = sub {
		print {$self->{server}->{client}} "NO Authentication timed out.\n";
		$self->{_log}->warn("Authentication timed out.");
		$self->_cleanup();
		exit 0;
	};

	# set alarm
	alarm($self->{auth_timeout});
	
	# read client data
	my $struct = $self->readStruct();

	# authenticate
	my $r = $self->{_chain}->authenticate($struct);
	if ($r) {
		$result_str = "OK Valid credentials.";
		$self->{_log}->info("Successfull authentication for user '" . $struct->{username} . "'.");
	} else {
		$self->{_log}->info("Unsuccessful authentication for user '" . $struct->{username}. "'.");
	}

	# reset alarm
	alarm(0);

	# write response back to client...
	print {$self->{server}->{client}} $result_str, "\n";

	# ... and shutdown client's socket...
	$self->_cleanup();

	return 1;
}

sub write_to_log_hook {
	my $self = shift;
	my $code = shift;
	
	if ($code <= 1) {
		$self->{_log}->info(@_);
	} else {
		$self->{_log}->debug(@_)
	}

	return 1;
}

sub setChain {
	my ($self, $obj) = @_;
	$self->{error} = "";
	unless (defined $obj && ref($obj) && $obj->isa("Net::OpenVPN::AuthChain")) {
		$self->{error} = "Invalid chain module.";
		return 0;
	}
	unless ($obj->isValidChain()) {
		$self->{error} = "Invalid chain: " . $obj->getError();
		return 0;
	}
	$self->{_chain} = $obj;
	return 1;
}

sub getChain {
	my ($self) = @_;
	$self->{error} = "";
	unless (defined $self->{_chain}) {
		$self->{error} = "Chain object is not assigned.";
		return undef;
	}
	return $self->{_chain};
}

sub getName {
	my ($self) = @_;
	return $self->{_myname};
}

sub setName {
	my ($self, $name) = @_;
	$self->{error} = "";
	unless (defined $name) {
		$self->{error} = "Invalid daemon name.";
		return 0;
	}
	$self->{_myname} = $name;
	return 1;
}

sub readStruct {
	my ($self) = @_;
	my $struct = {};
	$struct->{username} = "";
	my $i = 0;
	while ($i < MAXLINES && defined(my $line = $self->{server}->{client}->getline())) {
		$i++;
		$line = substr($line, 0, MAX_LINE_LENGTH);
		$line =~ s/\s+$//g;
		$line =~ s/^\s+//g;
		last unless (length($line));

		my @tmp = split(/=/, $line);
		my $key = shift(@tmp);
		$struct->{$key}	= join("=", @tmp);
	}
	
	if ($self->{_log}->is_debug()) {
		my $str = "";
		foreach my $key (sort keys %{$struct}) {
			$str .= " '$key' => '" . $struct->{$key} . "'";	
		}
		$self->{_log}->debug("Readed structure: " . $str);
	}

	return $struct;
}

# IO::Handle methods (used to catch output written by die && stuff)
sub TIEHANDLE {
	my $self = shift;
	return $self;
}

sub PRINT {
	my $self = shift;
	$self->{_log}->warn("Catched output to STDOUT/STDERR: ", @_);
	$self->{_log}->warn("This should not happen! Possible couses: Missing perl modules (running in chroot? Define \$extra_modules); OR BUG in your validation functions, if you're using AuthStruct module; OR BUG in openvpn_authd.pl/it's libraries.");
	return 1;
}

sub _cleanup {
	my ($self) = @_;

	if (defined $self->{server}->{client}) {
		$self->{server}->{client}->flush();
		$self->{server}->{client}->shutdown(2);
	}

	return 1;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>

=cut

1;
