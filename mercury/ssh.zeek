##! Implements SSH NPF

@load base/protocols/ssh

module Mercury::SSH;

redef record SSH::Info += {
	## Mercury NPF for client
	client_npf: string &log &optional;
	## Mercury NPF for server
	server_npf: string &log &optional;
};

function fmt_list(data: vector of string): string
	{
	return bytestring_to_hexstr(join_string_vec(data, ","));
	}

event ssh_capabilities(c: connection, cookie: string, cap: SSH::Capabilities) &priority=-1
	{
	if ( ! c?$ssh )
		return;

	local npf = fmt("ssh/(%s)(%s)(%s)(%s)(%s)(%s)(%s)(%s)(%s)(%s)",
		fmt_list(cap$kex_algorithms),
		fmt_list(cap$server_host_key_algorithms),
		fmt_list(cap$encryption_algorithms?$client_to_server ? cap$encryption_algorithms$client_to_server: vector()),
		fmt_list(cap$encryption_algorithms?$server_to_client ? cap$encryption_algorithms$server_to_client: vector()),
		fmt_list(cap$mac_algorithms?$client_to_server ? cap$mac_algorithms$client_to_server : vector()),
		fmt_list(cap$mac_algorithms?$server_to_client ? cap$mac_algorithms$server_to_client : vector()),
		fmt_list(cap$compression_algorithms?$client_to_server ? cap$compression_algorithms$client_to_server : vector()),
		fmt_list(cap$compression_algorithms?$server_to_client ? cap$compression_algorithms$server_to_client : vector()),
		fmt_list((cap?$languages && cap$languages?$client_to_server) ? cap$languages$client_to_server : vector()),
		fmt_list((cap?$languages && cap$languages?$server_to_client) ? cap$languages$server_to_client : vector()));

	if ( cap$is_server )
		c$ssh$server_npf = npf;
	else
		c$ssh$client_npf = npf;
	}
