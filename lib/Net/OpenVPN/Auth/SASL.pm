package Net::OpenVPN::Auth::SASL;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;
use Authen::SASL qw(Cyrus);

=head1 NAME SASL

Simple authentication and security layer (SASL) authentication backend module,
able to authenticate using cyrus-sasl native library. You need Authen::SASL::Cyrus
perl module installed in order to use this module. 

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<sasl_service> (string, "openvpn") SASL service name

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
	$self->{_name} = "SASL";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);
	bless($self, $class);

	# initialize object
	$self->clearParams();
	$self->setParams(@_);

	die "This driver is not yet finished.\n";

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();

	$self->{sasl_service} = "openvpn";
	$self->{mechanism} = "PLAIN";

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	
	$self->{error} = "SASL server is currently not implemented :)";
	return 0;
 
 
 	my $sasl = Authen::SASL->new (
		mechanism => $self->{mechanism},
		callback => {
			checkpass => \&checkpass,
			canonuser => \&canonuser,
    	}
 	);

 	# creating the Authen::SASL::Cyrus object
 	my $conn = $sasl->server_new("service","","ip;port local","ip;port remote");

 	# Clients first string (maybe "", depends on mechanism)
 	# Client has to start always
 	sendreply( $conn->server_start( &getreply() ) );

	while ($conn->need_step()) {
		sendreply( $conn->server_step( &getreply() ) );
 	}

	return 1 if ($conn->code() == 0);
	return 0;
}

=head1 AUTHOR

Brane F. Gracnar

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Authen::SASL>
L<Authen::SASL::Cyrus>

=cut

1;