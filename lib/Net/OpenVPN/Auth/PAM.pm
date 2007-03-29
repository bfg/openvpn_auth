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
package Net::OpenVPN::Auth::PAM;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;
use POSIX qw(ttyname);
use Authen::PAM qw(:constants);

=head1 NAME PAM

Pluggable authentication modules (PAM) authentication module, which is able
to authenticate using native PAM library.

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<pam_service> (string, "openvpn") - PAM service name (usualy name of file in /etc/pam.d directory)

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
	$self->{_name} = "PAM";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);
	bless($self, $class);

	# initialize object
	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();
	$self->{pam_service} = "openvpn";
	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	my $tty_name = ttyname(fileno(STDIN));

	# initialize pam object
	my $pam = Authen::PAM->new(
		$self->{pam_service},
		$struct->{username},

		# this pam conversation functiony is
		# completely stolen from
		# http://search.cpan.org/~nikip/Authen-PAM-0.16/PAM/FAQ.pod
		sub {
			my @res;
			while (@_) {
				my $code = shift;
				my $msg = shift;
				my $ans = "";

				$ans = $struct->{username} if ($code == PAM_PROMPT_ECHO_ON());
				$ans = $struct->{password} if ($code == PAM_PROMPT_ECHO_OFF());

				push (@res, (PAM_SUCCESS(), $ans));
			}

			push (@res, PAM_SUCCESS());
			return @res;
		}

	);

	unless (ref($pam)) {
		$self->{error} = "PAM initialization failed with error code $pam.";
		$self->{_log}->error($self->{error});
		return 0;
	}

	$pam->pam_set_item(PAM_TTY(), $tty_name);
	
	$self->{_log}->debug("Authenticating against PAM service '" . $self->{pam_service} . "' as user '" . $struct->{username} . "' with password '" . $struct->{password}. "'.");

	my $r = $pam->pam_authenticate();
	
	unless ($r == PAM_SUCCESS()) {
		$self->{error} = "PAM authentication failed: " . $pam->pam_strerror($r);
		return 0;	
	}

	return 1;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Authen::PAM>

=cut

1;