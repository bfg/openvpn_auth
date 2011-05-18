package Net::OpenVPN::Auth::DBI;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use DBI;
use Log::Log4perl;

# my modules
use Net::OpenVPN::PasswordValidator;

=head1 NAME DBI

SQL backend authentication module. This module can be used to authenticate against
all DBI supported backends, therefore is not mysql or postgresql specific.

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<persistent_connection> (boolean, 0) If set to value of 1, database connection will not be destroyed after each authentication request. Setting this to 1
can lead to better authentication performance, but it can lead to unpredictable results in case of database server restart.

B<dsn> (string, "DBI:mysql:database=openvpn;host=localhost") Data source name. Data source defines database type, database name,
database server (if any) and other connection flags (if any). See perldoc DBD::<YOUR_DATABASE_DRIVER> for your database specific instructions. 

B<username> (string, "") Database username

B<password> (string, "") Database password

B<sql> (string, "") SQL query used to fetch password from database. This query can be anything, that your DBI backend can process. SQL query can also
contain the following magic placeholders: B<%{username}, %{password}, %{cn}, %{untrusted_ip}, %{untrusted_port}>. DO NOT QUOTE magic placeholders. Quoting
is done by backend driver.

 EXAMPLE SQL:

 SELECT password FROM password_table
 	WHERE
 		username = %{username} AND
 		%{untrusted_port} BETWEEN 1024 AND 65536;

B<password_hash> (string, "CRYPTMD5") password hashing algorithm. List of supported and enabled password hashing algorithms can be obtained via
openvpn_authd.pl --list-pwalgs command.

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
	$self->{_name} = "DBI";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);
	$self->{_validator} = Net::OpenVPN::PasswordValidator->new();

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my $self = shift;
	$self->SUPER::clearParams();

	$self->{persistent_connection} = 0;
	$self->{dsn} = "DBI:mysql:database=openvpn;host=localhost";
	$self->{username} = "";
	$self->{password} = "";
	$self->{sql} = "";
	$self->{password_hash} = "CRYPTMD5";

	# database connection
	$self->{_conn} = undef;
	# prepared sql statemenet
	$self->{_sql} = undef;

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	my $r = 0;
	return 0 unless ($self->validateParamsStruct($struct));

	# fetch password hash
	my $pw_hash = $self->_getPwHash($struct);
	goto outta_auth unless (defined $pw_hash);

	# validate password hash
	$self->{_log}->debug("Validating password using " . $self->{password_hash} . " password hashing algorithm.");
	$r = $self->{_validator}->validatePassword(
		$pw_hash,
		$struct->{password},
		$self->{password_hash}
	);

	unless ($r) {
		$self->{error} = $self->{_validator}->getError();
		$self->{_log}->error($self->{error});
	}
	
	outta_auth:

	$self->_disconnect() unless ($self->{persistent_connection});
	return $r;
}

sub _connect {
	my ($self) = @_;

	# return immediately, if we're already connected
	if ($self->{persistent_connection} && $self->{_conn}) {
		return 1;
	} else {
		$self->{_conn} = undef;
		$self->{_sql} = undef;
	}
	
	$self->{error} = "";
	
	# database connection
	my $conn = undef;
	
	if (! (defined $self->{dsn} && length($self->{dsn}))) {
		$self->{error} = "Udefined property 'dsn'.";
	}
	elsif (! (defined $self->{username} && length($self->{username}))) {
		$self->{error} = "Udefined property 'username'.";	
	}
	elsif (! (defined $self->{password} && length($self->{password}))) {
		$self->{error} = "Udefined property 'password'.";
	}
	elsif (! (defined $self->{sql} && length($self->{sql}))) {
		$self->{error} = "Udefined property 'sql'.";
	}
	else {
		$self->{_log}->debug("Connecting to database identified by DSN '" . $self->{dsn} . "'.");
		$conn = DBI->connect(
			$self->{dsn},
			$self->{username},
			$self->{password},
			{
				RaiseError => 0,
				PrintError => 0
			},
		);
	}

	unless (defined $conn) {
		$self->{error} = "Unable to connect to SQL database: " . DBI->errstr() unless (length($self->{error}));
		$self->{_log}->error($self->{error});
		return 0;
	}

	# assign database connection to object instance
	$self->{_conn} = $conn;
	return 1;	
}

sub _disconnect {
	my ($self) = @_;
	if (defined $self->{_conn}) {
		$self->{_conn} = undef;
	}
	if (defined $self->{_sql}) {
		$self->{_sql} = undef; 
	}

	return 1;
}

sub _getPwHash {
	my ($self, $struct) = @_;
	return undef unless ($self->_connect());
	return undef unless ($self->_prepareSQL());
	
	my @x = $self->_getEArr($struct);
	if ($self->{_log}->is_debug()) {
		$self->{_log}->debug("Executing compiled SQL statement with parameters: ", join(", ", @x));
	}

	my $r = $self->{_sql}->execute(@x);

	unless ($r) {
		$self->{error} = "Error executing SQL: " . $self->{_conn}->errstr();
		$self->{_log}->error($self->{error});
		return undef;
	}

	my $num = $self->{_sql}->rows();
	$self->{_log}->debug("Query returned $num rows.");
	
	if ($num > 1) {
		$self->{_log}->warn("SQL query returned more than one row. Using only first one");
	}
	elsif ($num <1 ) {
		$self->{error} = "Username not found by SQL query.";
		$self->{_log}->error($self->{error});
		return undef;
	}
	
	# fetch only first row...
	@x = $self->{_sql}->fetchrow_array();
	
	unless (@x) {
		$self->{error} = "SQL client claims that returned more than 0 rows, but fetchrow() call failed. This should never happen.";
		$self->{_log}->error($self->{error});
		return undef;
	}
	
	$self->{_log}->debug("Fetched password: '" . $x[0] . "'.");
	unless (length($x[0])) {
		$self->{error} = "Zero length passwords are not allowed.";	
		$self->{_log}->error($self->{error});
		return undef;
	}

	return $x[0];	
}

sub _prepareSQL {
	my ($self) = @_;
	return 1 if (defined $self->{_sql});
	return 0 unless ($self->_connect());

	$self->{_log}->debug("Preparing/compiling SQL statement.");
	
	my $sql = $self->{sql};

	# remove any newline characters
	$sql =~ s/[\r\n]+//gm;

	# translate %{SOMETHING} into '?' (prepared sql statement placeholder)
	# and save SOMETHING into instance array
	@{$self->{_sql_select_names}} = ();
	$sql =~ s/%{(\w+)}/push(@{$self->{_sql_select_names}}, $1); '?' /ge;	

	$self->{_log}->debug("DBI prepared/overwritten SQL statement: '$sql'.");

	$self->{_sql} = $self->{_conn}->prepare($sql);
	
	unless ($self->{_sql}) {
		$self->{error} = "Error compiling SQL statement: " . $self->{_conn}->errstr();
		$self->{_log}->error($self->{error});
		return 0;
	}

	$self->{_log}->debug("SQL statement has been successfully compiled.");	
	return 1;	
}

sub _getEArr {
	my ($self, $struct) = @_;
	my @r;
	
	map {
		if (! exists($struct->{$_})) {
			$self->{_log}->warn("Invalid SQL magic placeholder %{$_}. Replacing with '' value.");
			push(@r, "");
		} else {
			push(@r, $struct->{$_});
		}
	} @{$self->{_sql_select_names}};

	return @r;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<DBI>
L<DBD::mysql>
L<DBD::Pg>

=cut

# This line is mandatory...
1;