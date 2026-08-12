package containerprofilecache

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetBundleConfig enables signed-bundle overlays. node-agent only needs the
// trust policy (the public-key fingerprints per fragment class): it VERIFIES
// fragment signatures, it never signs. No private key exists on the cluster.
// When the trust policy is set bundle assembly runs; otherwise the cache uses
// the single-CP overlay path. Wired from cmd/main.go after config load.
// maxBundleFragments caps the fragments assembled per bundle per reconcile tick.
const maxBundleFragments = 64

func (c *ContainerProfileCacheImpl) SetBundleConfig(policy *bundle.TrustPolicy) {
	c.bundleTrustPolicy = policy
}

func (c *ContainerProfileCacheImpl) bundlesEnabled() bool {
	return c.bundleTrustPolicy != nil
}

// signingEnforced reports whether unsigned or unverifiable user-supplied objects
// must be REFUSED (fail closed) rather than loaded with an alert. It folds the
// legacy per-object requireSignedObjects flag (EnableSignatureVerification) into
// the single trust-policy mode: a policy in enforce mode enforces, and the
// legacy flag still enforces for deployments that set it. Alert mode (or no
// policy) does not refuse.
func (c *ContainerProfileCacheImpl) signingEnforced() bool {
	if c.bundleTrustPolicy != nil && c.bundleTrustPolicy.Enforcing() {
		return true
	}
	return c.cfg.EnableSignatureVerification
}

// assembleUserBundle resolves a user-defined-profile label that names a signed
// bundle: it lists the bundle's fragments, verifies each against the trust
// policy, and deterministically assembles the admissible fragments into an
// in-memory composite. The composite is assembled from the just-verified
// fragments and is trusted in-process by the reconciler (no on-cluster
// signing).
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
			// Edge-triggered: alert once per OBSERVED clean→tamper transition and
			// re-arm on the next observed clean assembly (below). This is robust to
			// resourceVersions recurring after a delete/recreate — it keys on the
			// observed tamper STATE, not fragment identity.
			if _, wasTampered := c.bundleTampered.LoadOrStore(bundleKey, struct{}{}); !wasTampered {
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
	// Rollback guard: every fragment verified, but a still-validly-signed OLDER
	// fragment may have been replayed. Refuse the whole assembly if any leaf's
	// signed version is below the highest already accepted for its slot; this is
	// not a tamper (no R1016), it keeps the last verified composite.
	if verr := c.checkAndAdvanceVersions(ns, bundleName, manifest.Leaves); verr != nil {
		logger.L().Warning("signed bundle overlay refused: fragment rollback",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Error(verr))
		return nil, verr
	}

	// A clean assembly re-arms the edge-trigger so a later tamper alerts again.
	c.bundleTampered.Delete(bundleKey)

	// The composite is in-memory only (never stored), so it has no server
	// ResourceVersion. Use the Merkle root as its RV: it is a stable content hash
	// of the admissible leaf set, so the reconciler's RV fast-skip naturally
	// skips rebuilds while the fragments are unchanged and rebuilds when any
	// fragment (and hence the root) changes.
	composite.ResourceVersion = manifest.Root
	if composite.Annotations == nil {
		composite.Annotations = map[string]string{}
	}
	composite.Annotations[helpersv1.SyncChecksumMetadataKey] = manifest.Root

	// The composite is NOT signed on-cluster: node-agent only verifies fragment
	// signatures (offline vendor/operator keys). The composite is verified by
	// construction from the just-verified fragments and is trusted in-process by
	// the reconciler (it bypasses the flat verifyUserContainerProfile path).

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

// checkAndAdvanceVersions enforces per-slot monotonic versions. A slot is
// (namespace, bundle, class, name). In the first pass any leaf whose version is
// below the highest already accepted for its slot rejects the WHOLE assembly, so
// a replayed older fragment cannot slip in alongside current ones. Only if the
// whole set passes does the second pass advance the high-water-marks. The marks
// are in-memory, so they reset on restart — a rollback in the window right after
// a restart is not caught (documented limitation, not persisted here).
func (c *ContainerProfileCacheImpl) checkAndAdvanceVersions(ns, bundleName string, leaves []bundle.LeafRef) error {
	slot := func(lf bundle.LeafRef) string {
		return ns + "/" + bundleName + "/" + string(lf.Class) + "/" + lf.Name
	}
	for _, lf := range leaves {
		if prev, ok := c.bundleVersions.Load(slot(lf)); ok && lf.Version < prev.(int64) {
			return fmt.Errorf("%w: %s version %d < accepted %d", bundle.ErrFragmentRollback, slot(lf), lf.Version, prev.(int64))
		}
	}
	for _, lf := range leaves {
		key := slot(lf)
		for {
			prev, loaded := c.bundleVersions.LoadOrStore(key, lf.Version)
			if !loaded || lf.Version <= prev.(int64) {
				break
			}
			if c.bundleVersions.CompareAndSwap(key, prev, lf.Version) {
				break
			}
		}
	}
	return nil
}
