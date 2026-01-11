##! Implements STUN NPF

# Please only load me if the stun analyzer is available and loaded before this package.

module Mercury::STUN;

const LOG_TYPE_ATTRIBUTES: set[count] = {
	0x0006, # USERNAME
	0x0008, # MESSAGE_INTEGRITY
	0x0020, # XOR_MAPPED_ADDRESS
	0x8007,
	0x8008, # MS_VERSION
	0x8008, # SOFTWARE
	0x8028, # FINGERPRINT
	0x8037, # MS_APP_ID
	0x8070, # MS_IMPLEMENTATION_VERSION
	0xc003,
	0xC057, # GOOG_NETWORK_INFO,
	0xdaba
};

redef record STUN::Info += {
	# attribute tracking for mercury
	mercury_stun: string &default="";
	# Mercury STUN NPF
	npf: string &log &optional;
};

# Note - we have to happen _after_ STUN::string_attribute in the STUN package, as that is setting the sesision.
event STUN::string_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string, attr_type: count, attr_val: string) &priority=-5
	{
	if ( ! c?$stun )
		return;

	if ( attr_type == 0x8037 || attr_type == 0x8070 )
		c$stun$mercury_stun += fmt("(%04x%04x%s)", attr_type, |attr_val|, bytestring_to_hexstr(attr_val));
	else if ( attr_type in LOG_TYPE_ATTRIBUTES )
		c$stun$mercury_stun += fmt("(%04x)", attr_type);
	}

event STUN::mapped_address_attribute(c: connection, is_orig: bool, method: count, class: count, trans_id: string, attr_type: count, x_port: count, x_addr: addr) &priority=-5
	{
	if ( ! c?$stun )
		return;

	if ( attr_type in LOG_TYPE_ATTRIBUTES )
		c$stun$mercury_stun += fmt("(%04x)", attr_type);
	}

# ...but we need to happen before STUN::STUNPacket in the STUN package, as that removes the session.
# also - we need to cheat and call set_session, to fill out the npf line in the log.

module STUN;

event STUN::STUNPacket(c: connection, is_orig: bool, method: count, class: count, trans_id: string) &priority=5
	{
	local npf = "";
	if ( ! c?$stun )
		# No attributes
		npf = fmt("stun/1/(%02x)(%04x)(01)()", class, method);
	else
		npf = fmt("stun/1/(%02x)(%04x)(01)(%s)", class, method, c$stun$mercury_stun);

	set_session(c);

	c$stun$npf = npf;
	}
