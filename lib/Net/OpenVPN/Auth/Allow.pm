package Net::OpenVPN::Auth::Allow;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;

=head1 NAME Allow

Simple, dumb, "yes" saying authentication module.

B<Be *VERY* careful using it!>

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

This module doesn't accept any special parameters.
 B<It always returns successful authentication response>.

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

sub authenticate {
	my ($self, $struct) = @_;
	$self->{_log}->warn("Allow module always returns successfull authentication. Is this really what you want?");
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