package networkneighborhood

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/registry/file/networkmatch"
)

// neighborMatchesIP reports whether the observed IP matches any entry on
// the neighbor — either the deprecated singular IPAddress (back-compat)
// or any of the new IPAddresses[] entries (literal, CIDR, or '*' sentinel).
//
// Both the deprecated singular field and the new list field accept the
// SAME wildcard token vocabulary — i.e. a profile that sets
// IPAddress: "10.0.0.0/8" or IPAddress: "*" gets CIDR/sentinel matching
// just like the list form would. This unifies admission validation and
// runtime matching across both back-compat and current shapes.
//
// Built fresh per-call rather than cached. The functionCache layer in
// nn.go memoises the (containerID, address) tuple, so a hot rule firing
// on the same address won't repeatedly recompile the matcher.
func neighborMatchesIP(neighbor *v1beta1.NetworkNeighbor, observed string) bool {
	// Route the deprecated singular IPAddress through MatchIP as a single-element
	// slice so it gets the same canonicalisation (IPv6 forms, IPv4-mapped) as
	// the new IPAddresses[] entries. Symmetric with neighborMatchesDNS, which
	// also routes the deprecated singular DNS field through its matcher.
	if neighbor.IPAddress != "" && networkmatch.MatchIP([]string{neighbor.IPAddress}, observed) {
		return true
	}
	if len(neighbor.IPAddresses) > 0 {
		if networkmatch.MatchIP(neighbor.IPAddresses, observed) {
			return true
		}
	}
	return false
}

// neighborMatchesDNS reports whether the observed DNS name matches any
// entry on the neighbor — the deprecated singular DNS field, or any of
// the DNSNames[] entries (literal, leading-*, trailing-*, mid-⋯).
func neighborMatchesDNS(neighbor *v1beta1.NetworkNeighbor, observed string) bool {
	// Route the deprecated singular DNS through MatchDNS as a single-element
	// slice so it gets the same trailing-dot stripping + lowercasing as the
	// new DNSNames[] entries — back-compat shouldn't mean inconsistent
	// normalisation.
	if neighbor.DNS != "" && networkmatch.MatchDNS([]string{neighbor.DNS}, observed) {
		return true
	}
	if len(neighbor.DNSNames) > 0 {
		if networkmatch.MatchDNS(neighbor.DNSNames, observed) {
			return true
		}
	}
	return false
}

func (l *nnLibrary) wasAddressInEgress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Egress {
		if neighborMatchesIP(&cp.Spec.Egress[i], addressStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) wasAddressInIngress(containerID, address ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Ingress {
		if neighborMatchesIP(&cp.Spec.Ingress[i], addressStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) isDomainInEgress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Egress {
		if neighborMatchesDNS(&cp.Spec.Egress[i], domainStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) isDomainInIngress(containerID, domain ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	domainStr, ok := domain.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(domain)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Ingress {
		if neighborMatchesDNS(&cp.Spec.Ingress[i], domainStr) {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) wasAddressPortProtocolInEgress(containerID, address, port, protocol ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	// Reject out-of-range ports BEFORE narrowing to int32. CEL evaluates
	// port as int64, but TCP/UDP wire ports are uint16. A bogus value
	// like 4294967739 narrows to 443 and would match — return false
	// instead of letting the wrap silently succeed.
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	expectedPort := int32(portInt)
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Egress {
		egress := &cp.Spec.Egress[i]
		if !neighborMatchesIP(egress, addressStr) {
			continue
		}
		for _, portInfo := range egress.Ports {
			if portInfo.Protocol == v1beta1.Protocol(protocolStr) && portInfo.Port != nil && *portInfo.Port == expectedPort {
				return types.Bool(true)
			}
		}
	}

	return types.Bool(false)
}

func (l *nnLibrary) wasAddressPortProtocolInIngress(containerID, address, port, protocol ref.Val) ref.Val {
	if l.objectCache == nil {
		return types.NewErr("objectCache is nil")
	}

	containerIDStr, ok := containerID.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(containerID)
	}
	addressStr, ok := address.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(address)
	}
	portInt, ok := port.Value().(int64)
	if !ok {
		return types.MaybeNoSuchOverloadErr(port)
	}
	// See wasAddressPortProtocolInEgress for the int64→int32 wrap rationale.
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	expectedPort := int32(portInt)
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}

	cp, _, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}

	for i := range cp.Spec.Ingress {
		ingress := &cp.Spec.Ingress[i]
		if !neighborMatchesIP(ingress, addressStr) {
			continue
		}
		for _, portInfo := range ingress.Ports {
			if portInfo.Protocol == v1beta1.Protocol(protocolStr) && portInfo.Port != nil && *portInfo.Port == expectedPort {
				return types.Bool(true)
			}
		}
	}

	return types.Bool(false)
}
