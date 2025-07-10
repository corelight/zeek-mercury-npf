# @TEST-DOC: basic test verifying conn.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/tls/tls-1.2-handshake-failure.trace $PACKAGE %INPUT
# @TEST-EXEC: mv conn.log conn-v4.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/ftp/ipv6.trace $PACKAGE %INPUT
# @TEST-EXEC: mv conn.log conn-v6.log
# @TEST-EXEC: btest-diff conn-v4.log
# @TEST-EXEC: btest-diff conn-v6.log

