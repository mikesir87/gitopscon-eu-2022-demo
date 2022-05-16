package authorizeddomainpolicy

test_single_domain_with_ingress {
  allowed_domains := ["test.com"]
  ingress_domains := ["test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) == 0
}

test_single_domain_nonmatch_ingress {
  allowed_domains := ["other.com"]
  ingress_domains := ["test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_wildcard_ingress {
  allowed_domains := ["*.test.com"]
  ingress_domains := ["subdomain.test.com", "test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) == 0
}

test_wildcard_on_subdomain {
  allowed_domains := ["*.test.com"]
  ingress_domains := ["another-test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_wildcard_nonmatch_ingress {
  allowed_domains := ["*.other.com"]
  ingress_domains := ["subdomain.test.com", "test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_one_of_many_ingress {
  allowed_domains := ["test.com", "foo.com"]
  ingress_domains := ["test.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) == 0
}

test_one_of_many_nonmatch_ingress {
  allowed_domains := ["test.com", "foo.com"]
  ingress_domains := ["other.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_multi_match_ingress {
  allowed_domains := ["test.com", "foo.com", "bar.com"]
  ingress_domains := ["test.com", "foo.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) == 0
}

test_multi_match_nonmatch_ingress {
  allowed_domains := ["test.com", "foo.com", "bar.com"]
  ingress_domains := ["test.com", "other.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_subdomain_substring_ingress {
  allowed_domains := ["test.com"]
  ingress_domains := ["sometest.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) != 0
}

test_multilevel_wildcard {
  allowed_domains := ["*.example.com"]
  ingress_domains := ["test.subdomain.example.com"]
  input := input_obj(params_domains(allowed_domains), review_ingress(rules_domains(ingress_domains)))
  results := violation with input as input
  count(results) == 0
}


# ############# TEST CERTIFICATES ##############

test_single_domain_with_certificates {
  allowed_domains := ["test.com"]
  common_name := "test.com"
  dns_names := ["test.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  results := violation with input as input
  count(results) == 0
}

test_single_domain_nonmatch_in_dns_name_certificate {
  allowed_domains := ["test.com"]
  common_name := "test.com"
  dns_names := ["test2.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  results := violation with input as input
  count(results) == 1
}

test_single_domain_nonmatch_in_common_name_certificate {
  allowed_domains := ["test.com"]
  common_name := "test2.com"
  dns_names := ["test.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  results := violation with input as input
  count(results) == 1
}

test_wildcard_full_match_certificate {
  allowed_domains := ["*.test.com"]
  common_name := "test.com"
  dns_names := ["subdomain.test.com", "test.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  errors := violation with input as input
  count(errors) == 0
}

test_wildcard_nonmatch_in_all_names_certificate {
  allowed_domains := ["*.other.com"]
  common_name := "test.com"
  dns_names := ["subdomain.test.com", "test.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  errors := violation with input as input
  count(errors) == 3
}

test_wildcard_nonmatch_in_dns_names_certificate {
  allowed_domains := ["*.other.com"]
  common_name := "test.com"
  dns_names := ["subdomain.other.com", "other.com"]
  input := input_obj(params_domains(allowed_domains), review_certificate(common_name, dns_names))
  errors := violation with input as input
  count(errors) == 1
}

test_host_regexp_not_allowed_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "HostRegexp(`test.example.com`, `{subdomin:[a-z]+}.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_host_regexp_not_allowed_on_ingress_route {
  allowed_domains := ["test.example.com"]
  matchRule := "HostRegexp(`test.example.com`, `{subdomin:[a-z]+}.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_single_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "HostSNI(`test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "HostSNI(`test.example.com`, `sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "HostSNI(`test.example.com`) || HostSNI(`sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_mismatched_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "HostSNI(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_single_rule_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "HostSNI(`test.example.com`, `failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_split_rule_sni_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "HostSNI(`test.example.com`) || HostSNI(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_single_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "Host(`test.example.com`, `sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "Host(`test.example.com`) || Host(`sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_mismatched_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_single_rule_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`, `failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_split_rule_host_on_ingress_route_tcp {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`) || Host(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route_tcp(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_single_host_on_ingress_route {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_host_on_ingress_route {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "Host(`test.example.com`, `sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_multiple_host_on_ingress_route {
  allowed_domains := ["test.example.com", "*.test.example.com"]
  matchRule := "Host(`test.example.com`) || Host(`sub.test.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 0
}

test_mismatched_host_on_ingress_route {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_single_rule_host_on_ingress_route {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`, `failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 1
}

test_mixed_matching_in_split_rule_host_on_ingress_route {
  allowed_domains := ["test.example.com"]
  matchRule := "Host(`test.example.com`) || Host(`failure.example.com`)"
  input := input_obj(params_domains(allowed_domains), review_ingress_route(matchRule))
  errors := violation with input as input
  count(errors) == 1
}


############# HELPERS #############

review_ingress(rules) = out {
  out = {
    "kind": {
      "kind": "Ingress"
    },
    "object": {
      "kind": "Ingress",
      "apiVersion": "extensions/v1beta1",
      "metadata": {
        "name": "my-ingress",
      },
      "spec": {
        "rules": rules
      }
    }
  }
}

review_certificate(commonName, dnsNames) = out {
  out = {
    "kind": {
      "kind": "Certificate"
    },
    "object": {
      "kind": "Certificate",
      "apiVersion": "cert-manager.io/v1",
      "metadata": {
        "name": "my-certificate",
      },
      "spec": {
        "commonName": commonName,
        "dnsNames": dnsNames
      }
    }
  }
}

review_ingress_route_tcp(matchRule) = out {
  out = {
    "kind": {
      "kind": "IngressRouteTCP"
    },
    "object": {
      "kind": "IngressRouteTCP",
      "apiVersion": "traefik.containo.us/v1alpha1",
      "metadata": {
        "name": "my-ingress",
      },
      "spec": {
        "routes": [
          {
            "match": matchRule
          }
        ]
      }
    }
  }
}

review_ingress_route(matchRule) = out {
  out = {
    "kind": {
      "kind": "IngressRoute"
    },
    "object": {
      "kind": "IngressRoute",
      "apiVersion": "traefik.containo.us/v1alpha1",
      "metadata": {
        "name": "my-ingress",
      },
      "spec": {
        "routes": [
          {
            "match": matchRule
          }
        ]
      }
    }
  }
}

rules_domains(domain_list) = out {
  out = [
    rule_obj |
    rule_domain := domain_list[_]
    rule_obj := {"host": rule_domain}
  ]
}

params_domains(domains) = out {
  out = {
    "domains": domains
  }
}

input_obj(params, review) = out {
  out = {
    "parameters": params,
    "review": review
  }
}
