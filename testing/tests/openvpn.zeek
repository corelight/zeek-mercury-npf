# @TEST-DOC: basic test verifying stun.log

# @TEST-REQUIRES: zeek -NN | grep -q "ANALYZER_SPICY_OPENVPN"
# @TEST-EXEC: zeek -C -r $TRACES/openvpn_udp_tls-auth.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-openvpn_udp_tls-auth.log
# @TEST-EXEC: zeek -C -r $TRACES/openvpn-tcp-tls-auth.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssl.log ssl-openvpn-tcp-tls-auth.pcap.log
# @TEST-EXEC: btest-diff ssl-openvpn_udp_tls-auth.log
# @TEST-EXEC: btest-diff ssl-openvpn-tcp-tls-auth.pcap.log
