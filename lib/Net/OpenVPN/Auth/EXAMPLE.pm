package Net::OpenVPN::Auth::EXAMPLE;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;

=head1 NAME Allow

EXAMPLE module short description

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

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
	$self->{_name} = "EXAMPLE";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my $self = shift;
	$self->SUPER::clearParams();

	$self->{myVariable} = "value";
	$self->{myVariable2} = "value2";

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	$self->{_log}->debug("This is debug message...");
	$self->{_log}->info("This is info message...");
	$self->{_log}->warn("This is warning...");
	$self->{_log}->error("This is error message...");
	$self->{_log}->fatal("This is fatal error message...");

	$self->{error} = "This is sample error message returned back to authentication chain...";

	# if authentication succeeded, return 1, otherwise 0... 
	return 0;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>

=cut

# This line is mandatory...
1;