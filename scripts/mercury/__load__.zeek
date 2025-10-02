@load ./http
@load ./tcp

# this has to be loaded before the TLS script - to allow the TLS script to skip logging openvpn connections
@if ( Analyzer::has_tag("spicy_OpenVPN_UDP") )
@load base/misc/version
@load site/packages/zeek-spicy-openvpn
@endif

@load ./tls
@load ./quic

# Our scripts can only be loaded if the STUN scripts already are loaded....
# ifdef ( STUN::log_policy )

# Alternate approach. Will fail if package not installed in standard way.
# This seems a bit dirty.
@if ( Analyzer::has_tag("spicy_STUN") )
@load site/packages/zeek-spicy-stun
@load ./stun
@endif

@if ( Analyzer::has_tag("spicy_OpenVPN_UDP") )
@load ./openvpn
@endif
