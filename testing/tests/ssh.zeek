# @TEST-DOC: basic test verifying ssh.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/ssh/single-conn.trace $PACKAGE %INPUT
# @TEST-EXEC: mv ssh.log ssh-single-conn.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/ssh/ssh_kex_curve25519.pcap $PACKAGE %INPUT
# @TEST-EXEC: mv ssh.log ssh-ssh_kex_curve25519.log
# @TEST-EXEC: btest-diff ssh-single-conn.log
# @TEST-EXEC: btest-diff ssh-ssh_kex_curve25519.log

