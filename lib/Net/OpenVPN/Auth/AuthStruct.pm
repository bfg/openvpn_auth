package Net::OpenVPN::Auth::AuthStruct;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;

=head1 NAME AuthStruct

Authentication structure validating module. This module does not provide authentication,
but provides custom validation of openvpn client's connect data in conjunction with
openvpn client's certificate CN.

B<It is strongly recommended, that you put this module as the first module in authentication
chain and set required property on it.>

With this module you can B<validate> or even B<modify> values in authentication structure, becouse authentication
structure is passed as hash reference. The entire authentication framework uses Log::Log4perl based logging and if
you want to log any messages from your code, you can easyly do so - initialized log4perl object is passed to your
function as first argument, authentication structure hash reference is passed to your object as second argument.

B<VALIDATION FUNCTION>

Validation function is called with two arguments. First argument is initialized Log::Log4perl object, the second is authentication
structure hash reference. If validation succeeds, function must return 1, otherwise return value must be 0.

B<It is essential, that validation function
DOES NOT USE STDIN OR STDOUT, becouse they're opened to null device, STDERR is opened to daemon STDERR, therefore any output written to
STDERR will go to null device if daemon is running in background or to console if daemon is running using --no-daemon (default) switch.
If you want to print anything to log, use log4perl object, otherwise you'll need to open your own filehandle.
> 

 sub validator ($$) {
 	my $log = shift;
 	# $_[0] now holds authentication structure
 	
 	# if validation fails, return 0
 	return 0;
 	
 	# if validation succeeds, return 1
 	return 1;
 }

B<EXAMPLE VALIDATION FUNCTION> (define it inside openvpn_authd.conf)

 sub username_validator {
 	# fetch Log::Log4perl object
 	my $log = shift;
 
 	#
 	# we really hate user 'joe'.
 	#
 	if ($_[0]->{username} eq 'joe') {
 		$log->error("We don't like Joe. Returning authentication failure.");
 		
 		# return authentication module failure
 		return 0;
 	}
 
 	#
 	# Hm, we'll rewrite user 'kaya' to 'pretty_c_minus'
 	#
 	# Author's note: this person in fact really exists :)
 	#
 	elsif ($_[0]->{username} eq 'kaya') {
 		$log->warn("Rewriting username 'kaya' to 'pretty_c_minus'.")
 		$_[0]->{username} = 'pretty_c_minus';
 	}
 	
 	# return "authentication" success
 	return 1;
 }

B<EXAMPLE backend setup in openvpn_authd.conf>

 $auth_backends = {
 	struct_validator => {
 		required => 1,
 		driver => AuthStruct,
 		
 		username => \ &username_validator
 	},
 	
 	ldap_backend => {
 		required => 1,
 		sufficient => 1,
 
 		driver => 'LDAP',
 		# ... other parameters...
 	},
 };
 
 $auth_order = [
 	'struct_validator',
 	'ldap_backend'
 ];

B<LOADING VALIDATION FUNCTIONS FROM FILE>

Validation functions can be also loaded from separate file. You can load them using
B<load_validators("/path/to/filename");> directive in your openvpn_authd.conf configuration
file.

=head1 WARNING

This module gives you unlimited power trough usage of your own, in perl language written validators. You're able to
do anything that is possible in context of perl language. You can even call B<exit()> function, but then you'll shutdown
perl authentication worker process and authentication will fail. If you want to use B<open()> for inter process communication,
be shure to install your own B<local> SIGCHLD signal handler! However, the main purpose of this module is not to perform such hard-core
actions.

B<!!! REMEMBER !!!>

B<Bugs you produce in your validation functions become AUTHENTICATION PROCESS BUGS!>

=head1 RECOMMENDATION

If you use validation functions and you're not confident about your perl programming skills, be shure to run openvpn_authd in B<chrooted
jail environment>. You can achive this by setting B<$chroot> configuration variable to nonempty value.

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) This property is completely ignored in this module and is always defined as 0.

=over

=head2 Module specific parameters

B<username> (perl code reference, undef)

B<password> (perl code reference, undef)

B<common_name> (perl code reference, undef)

B<untrusted_ip> (perl code reference, undef)

B<untrusted_port> (perl code reference, undef)

B<If none of above listed properties are defined this module returns authentication success.>

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
	$self->{_name} = "Allow";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();
	
	$self->{username} = undef;
	$self->{password} = undef;
	$self->{common_name} = undef;
	$self->{untrusted_ip} = undef;
	$self->{untrusted_port} = undef;

	return 1;
}

# this module can never be sufficient 
sub isSufficient {
	my ($self) = @_;
	if ($self->{sufficient}) {
		$self->{_log}->warn("AuthStruct module does not provide authentication, therefore it cannot be sufficient for global authentication success. Returning error.");
	}
	return 0;
}

sub authenticate {
	my ($self, $struct) = @_;

	return 0 unless ($self->_validateUsername($struct));
	return 0 unless ($self->_validatePassword($struct));
	return 0 unless ($self->_validateCN($struct));
	return 0 unless ($self->_validateIP($struct));
	return 0 unless ($self->_validatePort($struct));

	return 1;
}

sub _validateUsername {
	my $self = shift;
	return $self->_runRef("username", @_);
}

sub _validatePassword {
	my $self = shift;
	return $self->_runRef("password", @_);
}

sub _validateCN {
	my $self = shift;
	return $self->_runRef("common_name", @_);
}

sub _validateIP {
	my $self = shift;
	return $self->_runRef("untrusted_ip", @_);
}

sub _validatePort {
	my $self = shift;
	return $self->_runRef("untrusted_port", @_);
}

sub _runRef {
	my $self = shift;
	my $name = shift;

	if (defined($self->{$name}) && ref($self->{$name}) eq 'CODE') {
		# safely run referenced code
		my $r = 0;
		$self->{_log}->debug("Running code reference for property $name.");
		eval {
			$r = $self->{$name}($self->{_log}, @_);
		};

		if ($@) {
			$self->{_log}->error("Unable to run code reference for property $name: $@");
			return 0;
		}

		return $r;
	}

	$self->{_log}->debug("No code reference defined for property $name, returning success.");
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