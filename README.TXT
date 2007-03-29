WHAT?

This package contains authentication server and client for excellent openvpn
(http://www.openvpn.net) VPN userland daemon. Currently you can authenticate
your openvpn client using the following authentication backends:

- LDAP
- Kerberos5
- any SQL database supported by perl DBI driver
- IMAPv4 server
- POP3 server
- plain file
- SASL library
- PAM library
- custom certificate validation algorithm.

SYSTEM REQUIREMENTS:

- perl (authentication server is written in perl)
- c compiler (for compiling authentication client)

You can install missing perl modules using your operating
system package manager or by running the following command:

perl -MCPAN -e shell
install <module name>

Required perl modules:
	- Log::Log4perl - for highly configurable logging
	- Log::Dispatch - Log4perl drivers
	- Net::Server - for simple and reliable network server infrastructure

Optional modules:
	- Net::LDAP - for ldap backend
	- IO::Socket::SSL - for providing secure transport for LDAP, IMAP and POP3
	                    backends
	- DBI and corresponding DBI module - for DBI/SQL backend
	- Authen::Krb5::Simple - for Kerberos5 backend
	- Authen::SASL - for sasl bind support in LDAP backend
	- Authen::SASL::Cyrus - for SASL backend
	- Authen::PAM - for PAM backend

Optional password validation perl modules:

These modules are used by File and DBI backends and possibly by LDAP backend
when using 'pass_attr' authentication method.

	- Crypt::PasswdMD5 - for validating md5 hashed crypt(3) passwords
	- Digest::MD5 - for validating md5 string hashes
	- Digest::SHA1 - for validation of sha1 string hashes
	- Crypt::SmbHash - for validation of ntlm hashes
	- Digest::Tiger - for validation of Tiger string hashes
	- Digest::Whirlpool - for validation of Whirlpool string hashes

INSTALLATION
1. Install, configure & test openvpn daemon (i guess you already did that)

2. Unpack openvpn_authd (i guess you already did that too)

3. Compile openvpn_authc
	cd "c" && make

4. Create default configuration file
	./bin/openvpn_authd.pl --default-conf > ./etc/openvpn_authd.conf

5. List supported authentication backends
	./bin/openvpn_authd.pl --list

6. Read authentication backend documentation
	./bin/openvpn_authd.pl --doc <DRIVER>

7. Adjust configuration your file
	vi ./etc/openvpn_authd.conf

8. Start server in non daemon and debug mode
	./openvpn_authd.pl --no-daemon --debug

9. Create file with username and password
	echo "joe" > /tmp/sample_auth.txt
	echo "joes_password" >> /tmp/sample_auth.txt

10. Create & adjust openvpn_authc configuration file
	./bin/openvpn_authc --default-config > /etc/openvpn_authc.conf
	vi /etc/openvpn_authc.conf

11. Check if everything works...
	export common_name="someuser.example.org"
	export untrusted_ip="1.2.3.4"
	export untrusted_port="3456"
	export script_type="auth-user-pass-verify"

	./bin/openvpn_authc -v /tmp/sample_auth.txt

12. Doesn't work? Check your syslog, there's alot of debug output...

13. Works? Hooray, configure your openvpn daemon to use openvpn_authc:

/etc/openvpn/openvpn-server.conf
--- snip ---
# use external additional authentication
# using openvpn_authd
auth-user-pass-verify /path/to/openvpn_authd/bin/openvpn_authc via-file
--- snip ---

14. Enjoy :)

LICENSE?

BSD license. See LICENSE.TXT.

FOUND A BUG?
Send error report to <bfg@frost.ath.cx>

WROTE NEW AUTHENTICATION BACKEND DRIVER?
Submit it via email to <bfg@frost.ath.cx>

DO YOU LIKE THIS SOFTWARE?

Send me a postcard :)

Brane F. Gracnar
Rakitovec 13
3263 Gorica pri Slivnici
Slovenia
Europe
