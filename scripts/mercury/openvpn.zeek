##! Implements OpenVPN NPF

# OpenVPN has to be loaded before this

@load base/protocols/ssl
@load ./tls

module Mercury::OpenVPN;

type MercuryOpenVPNInfo: record {
	## ID of lastt seen packet
	last_packet_id: count;
	## opcode
	op_code: count;
	## 0 if key_id == 0, 1 otherwise
	key_id: count;
};

redef record OpenVPN::Info += {
	## data needed for OpenVPN Mercury NPF
	mercury: MercuryOpenVPNInfo &optional;
	## HMAC length for OpenVPN Mercury NPF
	mercury_hmac_length: count &optional;
};

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=4
	{
	if ( ! info$c?$openvpn )
		return;

	if ( atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_MD5 || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_MD5 )
		info$c$openvpn$mercury_hmac_length = 16;
	else if ( atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA1 || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA1 )
		info$c$openvpn$mercury_hmac_length = 20;
	else if ( atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA256 || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA256 )
		info$c$openvpn$mercury_hmac_length = 32;
	else if ( atype == Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA512 || atype == Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA512 )
		info$c$openvpn$mercury_hmac_length = 64;
	}

event OpenVPN::control_message(c: connection, is_orig: bool, msg: OpenVPN::ControlMsg)
	{
	if ( ! c?$openvpn )
		c$openvpn = OpenVPN::Info();

	local m = MercuryOpenVPNInfo($last_packet_id = msg$packet_id,
	  $key_id = msg$key_id == 0 ? 0 : 1,
		$op_code = msg$opcode
	);
	c$openvpn$mercury = m;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=4
	{
	if ( ! c?$openvpn || ! c$openvpn?$mercury_hmac_length )
		return;

	local m = c$openvpn$mercury;
	local tls_ext_vec: string_vec = vector();
	local unsorted_ciphers = Mercury::TLS::degrease(ciphers);

	if ( c$ssl?$mercury_tls_client_exts )
		{
		local extensions = c$ssl$mercury_tls_client_exts;

		for ( i, ext in extensions )
			{
			# tls and tls/1
			if ( ext in Mercury::TLS::TLS_EXT_FIXED )
				tls_ext_vec += fmt("(%04x%04x%s)", ext, |c$ssl$mercury_tls_client_vals[ext]|, bytestring_to_hexstr(c$ssl$mercury_tls_client_vals[ext]));
			else
				tls_ext_vec += fmt("(%04x)", ext);
			}
		}

	# as we don't have a better log - let's put this into ssl.log for the moment
	c$ssl$npf = fmt("openvpn/(%02x)(%02x)(%02x%02x)(%02x)(%04x)(%s)(%s)", c$id$proto, m$last_packet_id+1, m$op_code, m$key_id, c$openvpn$mercury_hmac_length, version, join_string_vec(unsorted_ciphers, ""), join_string_vec(tls_ext_vec, ""));
	}
