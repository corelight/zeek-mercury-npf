##! Implements TCP NPF

@load base/protocols/conn

module Mercury::TCP;

redef record Conn::Info += {
	## Mercury TCP NPF
	npf: string &log &optional;
};

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	if ( pkt$is_orig == F )
		return;

	local header = get_current_packet_header();
	local npf = "tcp/";

	local options = Mercury::tcp_option_list();
	local string_options: string = "";
	for ( _, val in options )
		{
		if ( val$kind == 2 || val$kind == 3 )
			string_options += fmt("(%02x%02x%s)", val$kind, |val$data|+2, bytestring_to_hexstr(val$data));
		else
			string_options += fmt("(%02x)", val$kind);
		}

	if ( header?$ip && header?$tcp )
		npf += fmt("(40)(%s)(%02x)(%04x)(%s)", header$ip$id == 0 ? "00" : "", header$ip$ttl & 0xe0, header$tcp$win, string_options);
	else if ( header?$ip6 && header?$ tcp )
		npf += fmt("(60)(%s)(%02x)(%04x)(%s)", header$ip6$flow == 0 ? "00" : "", header$ip6$hlim & 0xe0, header$tcp$win, string_options);
	else # No ip header?
		return;

	c$conn$npf = npf;
	}
