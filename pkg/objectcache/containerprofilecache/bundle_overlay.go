package containerprofilecache

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sort"
	"strings"

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
// maxBundleFragments caps the fragments assembled per bundle per reconcile tick.
const maxBundleFragments = 64

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
	//
	// The storage server also IGNORES the List label selector, returning every
	// CP in the namespace — so the bundle membership MUST be re-checked here.
	// Without this, any user-defined-profile name would assemble ALL fragments
	// in the namespace (observed live: a client workload's profile lookup
	// assembled the server's fragments).
	var frags []*v1beta1.ContainerProfile
	var fpParts []string // fragment-set fingerprint: sorted name@resourceVersion
	for i := range list.Items {
		item := &list.Items[i]
		if item.Labels[bundle.LabelBundle] != bundleName {
			continue
		}
		if _, ok := item.Labels[bundle.LabelFragmentClass]; !ok {
			continue
		}
		// Bound the fragment count: assembly runs every reconcile tick (cosign
		// verify + gunzip + JSON per fragment), so an attacker who can create CPs
		// in the namespace could otherwise drive per-tick CPU/RPC without limit.
		if len(frags) >= maxBundleFragments {
			return nil, fmt.Errorf("bundle %q exceeds %d fragments", bundleName, maxBundleFragments)
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
		fpParts = append(fpParts, full.Name+"@"+full.ResourceVersion)
	}
	if len(frags) == 0 {
		return nil, nil // not a bundle — single-CP path handles it
	}

	bundleKey := ns + "/" + bundleName
	composite, manifest, err := bundle.AssembleAndVerify(bundleName, ns, frags, *c.bundleTrustPolicy)
	if err != nil {
		// A tampered fragment is a tamper event → R1016. Dedup on the fragment-set
		// fingerprint (sorted name@RV) held per bundle: a PERSISTENT bad state
		// alerts once, a DISTINCT tamper state re-alerts, and a clean re-assembly
		// clears the state (below) so a later tamper — even one whose fingerprint
		// recurs after a delete/recreate resets resourceVersions — alerts again.
		if errors.Is(err, bundle.ErrFragmentTampered) {
			sort.Strings(fpParts)
			fp := strings.Join(fpParts, ",")
			if prev, _ := c.bundleTamperFP.Load(bundleKey); prev != fp {
				c.bundleTamperFP.Store(bundleKey, fp)
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
	// A clean assembly clears the per-bundle tamper state so a later tamper
	// re-alerts (self-healing dedup — see the tamper branch above).
	c.bundleTamperFP.Delete(bundleKey)

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

	// Log root TRANSITIONS at Info (first assembly, fragment-set change) so the
	// bundle lifecycle is visible at default log level without drowning the log
	// in per-tick lines; unchanged re-assemblies stay at Debug.
	rootKey := ns + "/" + bundleName
	if prev, _ := c.bundleRoots.Load(rootKey); prev != manifest.Root {
		c.bundleRoots.Store(rootKey, manifest.Root)
		logger.L().Info("assembled signed bundle overlay",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.String("root", manifest.Root))
	} else {
		logger.L().Debug("assembled signed bundle overlay",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.String("root", manifest.Root))
	}
	return composite, nil
}
