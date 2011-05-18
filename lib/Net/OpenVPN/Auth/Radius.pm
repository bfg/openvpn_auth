package Net::OpenVPN::Auth::Radius;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;
use Authen::Radius;

=head1 NAME Radius

Radius authentication backend

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<host> (string, "localhost") radius server host

B<service> (string, "") radius service

B<secret> (string, "") radius secret

B<use_nas_ipaddr> (boolean, 0) Set authentication client's remote ip address as NAS IP?

B<timeout> (integer, 2) timeout for socket operations

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
	$self->{_name} = "Radius";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my $self = shift;
	$self->SUPER::clearParams();
	
	$self->{host} = "localhost";
	$self->{service} = "radius";
	$self->{secret} = "";
	$self->{use_nas_ipaddr} = 0;
	$self->{timeout} = 2;

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	$self->{_log}->debug("Creating radius auth object: host => '$self->{host}', secret => '$self->{secret}', service => '$self->{service}', timeout => $self->{timeout}.");
	my $radius = Authen::Radius->new(
		Host => $self->{host},
		Secret => $self->{secret},
		Service => $self->{service},
		Timeout => $self->{timeout},
		Debug => ($self->{_log}->is_debug() ? 1 : 0)
	);

	# validate password
	my $ip = ($self->{use_nas_ipaddr}) ? $struct->{untrusted_ip} : "127.0.0.1";
	$self->{_log}->debug("Performing Radius auth with NAS ip $ip");
	my $r = $radius->check_pwd(
		$struct->{username},
		$struct->{password},
		$ip
	);
	
	unless ($r) {
		$self->{error} = "Radius error: " . $radius->strerror();
		$self->{_log}->error($self->{error});
		return 0;
	}
	
	return $r;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Authen::Radius>

=cut

# This line is mandatory...
1;