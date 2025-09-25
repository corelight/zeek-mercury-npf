# @TEST-DOC: basic test verifying stun.log

# @TEST-REQUIRES: zeek -NN | grep -q "ANALYZER_SPICY_STUN"
# @TEST-EXEC: zeek -C -r $TRACES/stun-ice-testcall.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv stun.log stun-ice-testcall.log
# @TEST-EXEC: zeek-cut -m -m npf <stun-ice-testcall.log >stun-ice-testcall.cut
# @TEST-EXEC: btest-diff stun-ice-testcall.cut
