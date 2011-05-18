
all:
	make dynamic
	make static
	make debug

help:
	@echo ""
	@echo "OpenVPN authentication client openvpn_authc can be compiled"
	@echo ""
	@echo " - dynamically linked (make dynamic)"
	@echo " - statically linked - useful for chrooted openvpn daemon (make static)"
	@echo ""
	@echo "To compile, type:"
	@echo ""
	@echo "		make {dynamic|static|debug}"
	@echo ""

static:
	$(CC) $(CFLAGS) -O2 -Wall -static $(LDFLAFS) -g -o ../bin/openvpn_authc.static openvpn_auth_client.c
	strip ../bin/openvpn_authc.static

dynamic:
	$(CC) $(CFLAGS) -O2 -Wall $(LDFLAFS) -g -o ../bin/openvpn_authc openvpn_auth_client.c
	strip ../bin/openvpn_authc

debug:
	$(CC) $(CFLAGS) -O2 -Wall $(LDFLAFS) -g -o ../bin/openvpn_authc.debug openvpn_auth_client.c
