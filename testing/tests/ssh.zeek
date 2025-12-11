# @TEST-DOC: basic test verifying ssh.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/ssh/single-conn.trace $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m ts id.orig_h id.orig_p id.resp_h id.resp_p version client_npf server_npf < ssh.log > ssh-single-conn.log
# @TEST-EXEC: zeek -C -r $ZEEKTRACES/ssh/ssh_kex_curve25519.pcap $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m ts id.orig_h id.orig_p id.resp_h id.resp_p version client_npf server_npf < ssh.log > ssh-ssh_kex_curve25519.log
# @TEST-EXEC: btest-diff ssh-single-conn.log
# @TEST-EXEC: btest-diff ssh-ssh_kex_curve25519.log

