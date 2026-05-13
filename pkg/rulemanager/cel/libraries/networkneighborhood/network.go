package networkneighborhood

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/profilehelper"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Each CEL function performs the same shape of work:
//   1. resolve container profile + checksum
//   2. fetch or build cached compiled matchers for this profile version
//   3. walk the relevant direction's neighbor slice, asking each compiled
//      matcher whether the observation matches
//
// The matcherCache means we pay CompileIP / CompileDNS at most once per
// profile checksum per neighbor — not on every CEL function-cache miss.

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
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Egress {
		if cm.ipMatcher(cp.Spec.Egress, i, &cm.egress).Match(addressStr) {
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
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Ingress {
		if cm.ipMatcher(cp.Spec.Ingress, i, &cm.ingress).Match(addressStr) {
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
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Egress {
		if cm.dnsMatcher(cp.Spec.Egress, i, &cm.egress).Match(domainStr) {
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
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Ingress {
		if cm.dnsMatcher(cp.Spec.Ingress, i, &cm.ingress).Match(domainStr) {
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
	// See network.go on feat/network-wildcards for the int64→int32 wrap rationale.
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	expectedPort := int32(portInt)
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Egress {
		egress := &cp.Spec.Egress[i]
		if !cm.ipMatcher(cp.Spec.Egress, i, &cm.egress).Match(addressStr) {
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
	if portInt < 0 || portInt > 65535 {
		return types.Bool(false)
	}
	expectedPort := int32(portInt)
	protocolStr, ok := protocol.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(protocol)
	}
	cp, checksum, err := profilehelper.GetContainerProfile(l.objectCache, containerIDStr)
	if err != nil {
		return cache.NewProfileNotAvailableErr("%v", err)
	}
	cm := l.matcherCache.getOrBuild(containerIDStr, checksum, cp)
	for i := range cp.Spec.Ingress {
		ingress := &cp.Spec.Ingress[i]
		if !cm.ipMatcher(cp.Spec.Ingress, i, &cm.ingress).Match(addressStr) {
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
