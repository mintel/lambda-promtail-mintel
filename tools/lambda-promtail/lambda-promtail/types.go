package main

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

// CommaSeparatedStringSet represents a set of strings that unmarshals from a comma-separated string in JSON.
type CommaSeparatedStringSet map[string]struct{}

func (set *CommaSeparatedStringSet) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	fragments := strings.Split(s, ",")
	m := make(CommaSeparatedStringSet, len(fragments))
	for _, f := range fragments {
		m[f] = struct{}{}
	}
	*set = m
	return nil
}

// Contains returns true if set contains s.
func (set CommaSeparatedStringSet) Contains(s string) bool {
	_, ok := set[s]
	return ok
}

// CommaSeparatedCIDRSet represents a set of IP prefixes (a.k.a. CIDR blocks) that unmarshals from a comma-separated string in JSON.
type CommaSeparatedCIDRSet map[netip.Prefix]struct{}

func (set *CommaSeparatedCIDRSet) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	fragments := strings.Split(s, ",")
	m := make(CommaSeparatedCIDRSet, len(fragments))
	for _, f := range fragments {
		m[netip.MustParsePrefix(f)] = struct{}{}
	}
	*set = m
	return nil
}

// Contains returns true if set contains s.
func (set CommaSeparatedCIDRSet) Contains(p netip.Prefix) bool {
	_, ok := set[p]
	return ok
}

// Match returns true if ip matches any of the prefixes in this set.
func (set CommaSeparatedCIDRSet) Match(ip netip.Addr) bool {
	for prefix, _ := range set {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// CommaSeparatedHostnameSet represents a set of hostnames that unmarshals from a comma-separated string in JSON.
// Hostnames can include wildcards e.g. "*.example.org".
type CommaSeparatedHostnameSet struct {
	pattern string
	r       *regexp.Regexp
}

func (set *CommaSeparatedHostnameSet) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	fragments := strings.Split(s, ",")
	for i, f := range fragments {
		f = strings.ReplaceAll(f, "*", "@") // Replace wildcards with a temp symbol that isn't a regex control character.
		f = regexp.QuoteMeta(f)             // Quote the dots in the hostname.
		f = strings.ReplaceAll(f, "@", ".*")
		fragments[i] = f
	}
	pattern := "^(" + strings.Join(fragments, "|") + ")$"
	r, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	*set = CommaSeparatedHostnameSet{
		pattern: pattern,
		r:       r,
	}
	return nil
}

// Match returns true if matches any of the hostnames in this set, including by wildcard.
func (set *CommaSeparatedHostnameSet) Match(hostname string) bool {
	if set == nil {
		return false
	}
	return set.r.MatchString(hostname)
}

func (set *CommaSeparatedHostnameSet) IsZero() bool {
	if set == nil {
		return true
	}
	return set.pattern == "^()$"
}

// RegexpString represents a JSON-encoded regexp pattern that can be unmarshaled.
type RegexpString struct {
	*regexp.Regexp
	Value string
}

func (rs *RegexpString) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	var p *regexp.Regexp
	if s != "" {
		p, err = regexp.Compile(s)
		if err != nil {
			return err
		}
	}
	*rs = RegexpString{
		Value:  s,
		Regexp: p,
	}
	return nil
}

func (rs *RegexpString) String() string {
	return rs.Value
}

func (rs *RegexpString) IsZero() bool {
	if rs == nil {
		return true
	}
	if rs.Value == "" || rs.Regexp == nil {
		return true
	}
	return false
}
