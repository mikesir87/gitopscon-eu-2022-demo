package authorizeddomainpolicy

violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	host := input.review.object.spec.rules[_].host
	valid_ingress_hosts := input.parameters.domains
	not fqdn_matches_any(host, valid_ingress_hosts)
	msg := sprintf("Unauthorized host on Ingress - %q", [host])
}

# Validate dnsNames on Certificate object
violation[{"msg" : msg}] {
	input.review.kind.kind == "Certificate"
	host := input.review.object.spec.dnsNames[_]
	valid_hosts := input.parameters.domains
	not fqdn_matches_any(host, valid_hosts)
	msg := sprintf("Unauthorized dnsName on Certificate - %q", [host])
}

# Validate commonName on Certificate object
violation[{"msg" : msg}] {
	input.review.kind.kind == "Certificate"
	host := input.review.object.spec.commonName
	valid_hosts := input.parameters.domains
	not fqdn_matches_any(host, valid_hosts)
	msg := sprintf("Unauthorized commonName on Certificate - %q", [host])
}

# Validate Traefik's IngressRoute/IngressRouteTCP matches have valid hostnames
violation[{"msg" : msg}] {
	is_traefik_ingress_route

	# Extract the hosts out of the rules
	hostRule := input.review.object.spec.routes[_].match
	sniRule := regex.find_n("(HostSNI|Host|HostHeader)\\(`[a-z0-9\\.`,\\s]+`\\)", hostRule, -1)[_]
	hostWithTicks := regex.find_n("`[a-z0-9\\.]+`", sniRule, -1)[_]
	host := trim(hostWithTicks, "`")
	
	valid_hosts := input.parameters.domains
	not fqdn_matches_any(host, valid_hosts)
	msg := sprintf("Unauthorized host on IngressRouteTCP - %q", [host])
}

# Deny usage of the HostRegexp rule, as it's simply too hard to validate right now
violation[{"msg" : msg}] {
	is_traefik_ingress_route
	hostRule := input.review.object.spec.routes[_].match
	contains(hostRule, "HostRegexp")
	msg := sprintf("Usage of HostRegexp rules on IngressRoute/IngressRouteTCP is not allowed - %q", [hostRule])
}

fqdn_matches_any(str, patterns) {
	fqdn_matches(str, patterns[_])
}

# Match *.<domain> against *.<domain> with support for multi-level wildcarding
fqdn_matches(str, pattern) {

	# Validate the pattern starts with *.
	pattern_parts := split(pattern, ".")
	pattern_parts[0] == "*"
	
	# Create an array that contains each segment of the pattern, minus the wildcard
	pattern_minus_wildcard := split(trim(pattern, "*."), ".")

	# Create an array of the incoming string, but to the same length of the pattern
	str_parts := split(str, ".")
	str_slice := array.slice(str_parts, count(str_parts) - count(pattern_minus_wildcard), count(str_parts))

	# Validate the two arrays are equal
	arrays_equal(str_slice, pattern_minus_wildcard)	
}

# Match *.<domain> against <domain>
fqdn_matches(str, pattern) {
	pattern_parts := split(pattern, ".")
	pattern_parts[0] == "*"
	suffix := trim(pattern, "*.")
	suffix == str
}

# Match <domain> against <domain>
fqdn_matches(str, pattern) {
	not contains(pattern, "*")
	str == pattern
}

is_traefik_ingress_route {
	input.review.kind.kind == "IngressRouteTCP"
}

is_traefik_ingress_route {
	input.review.kind.kind == "IngressRoute"
}

arrays_equal(arr1, arr2) {
	not elements_differ(arr1, arr2)
}

elements_differ(arr1, arr2) {
	some i
	arr1[i] != arr2[i]
}
