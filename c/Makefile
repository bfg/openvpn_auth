all:
	@echo ""
	@echo "OpenVPN authentication client openvpn_authc can be compiled"
	@echo ""
	@echo " - dynamically linked (make dynamic)"
	@echo " - statically linked - useful for chrooted openvpn daemon (make static)"
	@echo ""
	@echo "To compile, type:"
	@echo ""
	@echo "		make {dynamic|static}"
	@echo ""

static:
	$(CC) $(CFLAGS) -Wall -static $(LDFLAFS) -g -o ../bin/openvpn_authc openvpn_auth_client.c
	strip ../bin/openvpn_authc

dynamic:
	$(CC) $(CFLAGS) -Wall $(LDFLAFS) -g -o ../bin/openvpn_authc openvpn_auth_client.c
	strip ../bin/openvpn_authc
