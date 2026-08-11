package bundle

import (
	"encoding/json"
	"errors"
	"fmt"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
)

// RuleClass declares the blast radius of a signed Rules fragment: a cluster
// class fragment contributes detection rules to every namespace, a namespace
// class fragment only to the namespace it was signed for.
type RuleClass string

const (
	// RuleClassCluster fragments apply cluster-wide.
	RuleClassCluster RuleClass = "cluster"
	// RuleClassNamespace fragments apply only inside their own namespace and
	// override the cluster-wide rule carrying the same rule ID there.
	RuleClassNamespace RuleClass = "namespace"
)

// LabelRuleClass declares a Rules fragment's class (cluster|namespace). It sits
// in metadata.labels, which IS part of the signed content, so the class cannot
// be changed without invalidating the signature.
const LabelRuleClass = "signature.kubescape.io/rule-class"

// Rule-fragment admissibility failure sentinels. They complement the
// ContainerProfile fragment sentinels in verify.go and deliberately reuse
// ErrFragmentUnsigned / ErrFragmentTampered / ErrSignerNotTrusted / ErrNoClass
// so callers can treat both fragment kinds uniformly.
var (
	ErrRuleClassNotAllowed = errors.New("rule class not present in trust policy")
	ErrRuleIDNotAllowed    = errors.New("rule ID not permitted for this rule class")
	ErrRuleNamespaceEmpty  = errors.New("namespace-scoped rule fragment has no namespace")
)

// RuleClassPolicy is the admissibility rule for one rule class: which signer
// identities may author it and which rule IDs it may carry.
type RuleClassPolicy struct {
	Signers        []string `json:"signers"`
	AllowedRuleIDs []string `json:"allowedRuleIDs"`
}

func (p RuleClassPolicy) allowsSigner(id string) bool {
	for _, s := range p.Signers {
		if s == id {
			return true
		}
	}
	return false
}

// allowsRuleID reports whether the class may carry the given rule ID. The
// wildcard entry "*" admits any ID.
func (p RuleClassPolicy) allowsRuleID(id string) bool {
	for _, s := range p.AllowedRuleIDs {
		if s == id || s == "*" {
			return true
		}
	}
	return false
}

// VerifiedRules is the admitted view of a signed Rules object. Every field is
// derived from the VERIFIED content, never from the stored carrier object.
type VerifiedRules struct {
	Rules       []rulemanagertypesv1.Rule
	Class       RuleClass
	Signer      string
	Namespace   string // the VERIFIED source namespace (from signed content)
	ClusterWide bool   // true iff Class == RuleClassCluster
}

// rulesEmbeddedView is the canonical signed content layout produced by the
// Rules adapter's GetContent (profiles.RulesAdapter).
type rulesEmbeddedView struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec rulemanagertypesv1.RulesSpec `json:"spec"`
}

// AdmitRulesFragment runs the full admissibility check on one Rules object: it
// must be signed, verify cleanly, declare a class the trust policy knows, be
// signed by a signer that class trusts, and carry only rule IDs that class is
// allowed to ship.
//
// When the object carries embedded signed content (signed with --embed-content),
// the EMBEDDED bytes are the verified source of truth: name, namespace, labels
// (i.e. the class) and the rule list all come from them. This is what makes the
// namespace scoping sound — an attacker who copies a validly signed namespace
// fragment into another namespace cannot re-scope it, because the namespace the
// agent acts on is the signed one, and signature.VerifyObjectAllowUntrusted
// additionally binds the embedded name+namespace to the carrier object.
func AdmitRulesFragment(r *rulemanagertypesv1.Rules, policy TrustPolicy) (VerifiedRules, error) {
	if r == nil {
		return VerifiedRules{}, fmt.Errorf("nil Rules object")
	}
	adapter := profiles.NewRulesAdapter(r)
	if !signature.IsSigned(adapter) {
		return VerifiedRules{}, fmt.Errorf("%w: %q", ErrFragmentUnsigned, r.Name)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		if errors.Is(err, signature.ErrSignatureMismatch) {
			return VerifiedRules{}, fmt.Errorf("%w: %q: %v", ErrFragmentTampered, r.Name, err)
		}
		return VerifiedRules{}, fmt.Errorf("verify rules fragment %q: %w", r.Name, err)
	}

	// Establish the verified view: embedded content when present, else the
	// stored object.
	name := r.Name
	namespace := r.Namespace
	labels := r.Labels
	rules := r.Spec.Rules
	if embedded, present, embErr := signature.EmbeddedContent(adapter); present {
		if embErr != nil {
			return VerifiedRules{}, fmt.Errorf("embedded content of %q: %w", r.Name, embErr)
		}
		var view rulesEmbeddedView
		if err := json.Unmarshal(embedded, &view); err != nil {
			return VerifiedRules{}, fmt.Errorf("parse embedded content of %q: %w", r.Name, err)
		}
		name = view.Metadata.Name
		namespace = view.Metadata.Namespace
		labels = view.Metadata.Labels
		rules = view.Spec.Rules
	}

	class := RuleClass(labels[LabelRuleClass])
	if class == "" {
		return VerifiedRules{}, fmt.Errorf("%w: %q", ErrNoClass, name)
	}
	rpol, ok := policy.RuleClasses[class]
	if !ok {
		return VerifiedRules{}, fmt.Errorf("%w: class %q (fragment %q)", ErrRuleClassNotAllowed, class, name)
	}

	sig, err := signature.GetObjectSignature(adapter)
	if err != nil {
		return VerifiedRules{}, fmt.Errorf("read signature of %q: %w", name, err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return VerifiedRules{}, fmt.Errorf("signer identity of %q: %w", name, err)
	}
	if !rpol.allowsSigner(signer) {
		return VerifiedRules{}, fmt.Errorf("%w: signer %q, class %q (fragment %q)", ErrSignerNotTrusted, signer, class, name)
	}

	for _, rule := range rules {
		if !rpol.allowsRuleID(rule.ID) {
			return VerifiedRules{}, fmt.Errorf("%w: rule %q, class %q (fragment %q)", ErrRuleIDNotAllowed, rule.ID, class, name)
		}
	}

	if class == RuleClassNamespace && namespace == "" {
		return VerifiedRules{}, fmt.Errorf("%w: fragment %q", ErrRuleNamespaceEmpty, name)
	}

	return VerifiedRules{
		Rules:       rules,
		Class:       class,
		Signer:      signer,
		Namespace:   namespace,
		ClusterWide: class == RuleClassCluster,
	}, nil
}

// RulesSignerID returns the trust-policy signer identity of a signed Rules
// object — the signing public-key fingerprint (key:<sha256(PKIX(pub))>).
// Exposed for authoring trust policies and tests.
func RulesSignerID(r *rulemanagertypesv1.Rules) (string, error) {
	sig, err := signature.GetObjectSignature(profiles.NewRulesAdapter(r))
	if err != nil {
		return "", err
	}
	return signerIdentity(sig)
}
