@load ./http
@load ./tcp
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
