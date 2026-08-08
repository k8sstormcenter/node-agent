package containerprofilecache

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetBundleConfig enables signed-bundle overlays. Both a trust policy and a
// signing key must be set for bundle assembly to run; otherwise the cache uses
// the single-CP overlay path. Wired from cmd/main.go after config load.
func (c *ContainerProfileCacheImpl) SetBundleConfig(policy *bundle.TrustPolicy, signingKey *ecdsa.PrivateKey) {
	c.bundleTrustPolicy = policy
	c.bundleSigningKey = signingKey
}

func (c *ContainerProfileCacheImpl) bundlesEnabled() bool {
	return c.bundleTrustPolicy != nil && c.bundleSigningKey != nil
}

// assembleUserBundle resolves a user-defined-profile label that names a signed
// bundle: it lists the bundle's fragments, verifies each against the trust
// policy, deterministically assembles them, and re-signs the composite with the
// cluster key so the flat verify/tamper path (verifyUserContainerProfile) then
// protects it.
//
// Returns:
//   - (composite, nil) when a bundle was assembled — use it as the overlay;
//   - (nil, nil)        when bundles are disabled, or no class-labeled fragments
//     exist for this name (fall back to the single-CP path);
//   - (nil, err)        when fragments exist but fail verification/assembly. A
//     tampered fragment additionally raises R1016 (deduped).
func (c *ContainerProfileCacheImpl) assembleUserBundle(ctx context.Context, ns, bundleName, wlid string) (*v1beta1.ContainerProfile, error) {
	if !c.bundlesEnabled() || bundleName == "" {
		return nil, nil
	}

	var (
		list *v1beta1.ContainerProfileList
		lerr error
	)
	_ = c.refreshRPC(ctx, func(rctx context.Context) error {
		list, lerr = c.storageClient.ListContainerProfiles(rctx, ns, metav1.ListOptions{
			LabelSelector: bundle.LabelBundle + "=" + bundleName,
		})
		return lerr
	})
	if lerr != nil || list == nil {
		return nil, lerr
	}

	// The storage server's List serves items from its metadata table WITHOUT
	// loading the payload — the returned objects are spec-stripped. Hashing those
	// would flag every signed fragment as tampered. Use the List only to discover
	// the fragment set (names + labels round-trip fine) and GET each fragment for
	// its full spec.
	var frags []*v1beta1.ContainerProfile
	for i := range list.Items {
		item := &list.Items[i]
		if _, ok := item.Labels[bundle.LabelFragmentClass]; !ok {
			continue
		}
		var (
			full *v1beta1.ContainerProfile
			gerr error
		)
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			full, gerr = c.storageClient.GetContainerProfile(rctx, ns, item.Name)
			return gerr
		})
		if gerr != nil || full == nil {
			// Transient fetch failure: fail this assembly attempt as operational
			// (NOT tamper — no R1016); the caller retries on the next tick.
			return nil, fmt.Errorf("fetch bundle fragment %q: %w", item.Name, gerr)
		}
		frags = append(frags, full)
	}
	if len(frags) == 0 {
		return nil, nil // not a bundle — single-CP path handles it
	}

	composite, manifest, err := bundle.AssembleAndVerify(bundleName, ns, frags, *c.bundleTrustPolicy)
	if err != nil {
		// A tampered fragment is a tamper event → R1016 (deduped on the bundle
		// name + fragment count, so a persistent bad fragment alerts once).
		if errors.Is(err, bundle.ErrFragmentTampered) {
			key := tamperKey("ContainerProfileBundle", ns, bundleName, "")
			if _, already := c.tamperEmitted.LoadOrStore(key, struct{}{}); !already {
				c.emitTamperAlert(bundleName, ns, wlid, "ContainerProfile bundle", err)
			}
		}
		logger.L().Warning("signed bundle overlay failed verification/assembly",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.Error(err))
		return nil, err
	}
	// A clean assembly clears any prior tamper flag for this bundle.
	c.tamperEmitted.Delete(tamperKey("ContainerProfileBundle", ns, bundleName, ""))

	// The composite is in-memory only (never stored), so it has no server
	// ResourceVersion. Use the Merkle root as its RV: it is a stable content hash
	// of the admissible leaf set, so the reconciler's RV fast-skip naturally
	// skips rebuilds while the fragments are unchanged and rebuilds when any
	// fragment (and hence the root) changes.
	composite.ResourceVersion = manifest.Root

	// Internal re-sign with the cluster key so the composite is a normally-signed
	// CP the downstream verify/tamper path re-checks on every load.
	if err := bundle.SignComposite(composite, signature.WithPrivateKey(c.bundleSigningKey)); err != nil {
		logger.L().Warning("failed to re-sign assembled bundle composite",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Error(err))
		return nil, err
	}

	logger.L().Debug("assembled signed bundle overlay",
		helpers.String("bundle", bundleName),
		helpers.String("namespace", ns),
		helpers.Int("fragments", len(frags)),
		helpers.String("root", manifest.Root))
	return composite, nil
}
