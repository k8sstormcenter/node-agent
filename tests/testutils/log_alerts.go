package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

// LogAlert represents a full alert parsed from node-agent stdout exporter logs.
type LogAlert struct {
	RuleID    string
	AlertName string
	Namespace string
	Container string
	PodName   string
	Comm      string
	// DNS-specific (R0005)
	Domain    string
	Addresses []string
	// Network-specific (R0011)
	DstIP string
	Port  string
	Proto string
	// Full message from arguments
	Message string
}

// GetLogAlerts reads node-agent pod logs, parses the stdout exporter JSON,
// and returns alerts filtered by namespace.
func GetLogAlerts(namespace string) ([]LogAlert, error) {
	k8sClient := k8sinterface.NewKubernetesApi()

	pods, err := k8sClient.KubernetesClient.CoreV1().Pods("").List(
		context.TODO(), metav1.ListOptions{
			LabelSelector: "app=node-agent",
		})
	if err != nil {
		return nil, fmt.Errorf("list node-agent pods: %w", err)
	}

	var alerts []LogAlert
	for _, pod := range pods.Items {
		buf := &bytes.Buffer{}
		req := k8sClient.KubernetesClient.CoreV1().RESTClient().
			Get().
			Namespace(pod.Namespace).
			Name(pod.Name).
			Resource("pods").
			SubResource("log").
			VersionedParams(&v1.PodLogOptions{
				Container: "node-agent",
			}, scheme.ParameterCodec)

		rc, err := req.Stream(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("stream logs for %s: %w", pod.Name, err)
		}
		_, err = io.Copy(buf, rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read logs for %s: %w", pod.Name, err)
		}

		parsed := parseLogAlerts(buf.String(), namespace)
		alerts = append(alerts, parsed...)
	}
	return alerts, nil
}

// parseLogAlerts extracts alert entries from logrus JSON lines.
func parseLogAlerts(logs, namespace string) []LogAlert {
	var alerts []LogAlert
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		ruleID, _ := entry["RuleID"].(string)
		if ruleID == "" {
			continue
		}

		// Extract RuntimeK8sDetails
		k8s, _ := entry["RuntimeK8sDetails"].(map[string]interface{})
		ns, _ := k8s["namespace"].(string)
		if namespace != "" && ns != namespace {
			continue
		}

		container, _ := k8s["containerName"].(string)
		podName, _ := k8s["podName"].(string)

		// Extract BaseRuntimeMetadata
		base, _ := entry["BaseRuntimeMetadata"].(map[string]interface{})
		alertName, _ := base["alertName"].(string)
		args, _ := base["arguments"].(map[string]interface{})

		// Extract identifiers for comm
		comm := ""
		if ids, ok := base["identifiers"].(map[string]interface{}); ok {
			if proc, ok := ids["process"].(map[string]interface{}); ok {
				comm, _ = proc["name"].(string)
			}
		}

		la := LogAlert{
			RuleID:    ruleID,
			AlertName: alertName,
			Namespace: ns,
			Container: container,
			PodName:   podName,
			Comm:      comm,
		}

		if args != nil {
			la.Domain, _ = args["domain"].(string)
			la.Message, _ = args["message"].(string)
			la.Proto, _ = args["protocol"].(string)
			if la.Proto == "" {
				la.Proto, _ = args["proto"].(string)
			}

			// IP: from arguments.ip (R0011) or identifiers.network.dstIP (R0005)
			if ip, ok := args["ip"].(string); ok {
				la.DstIP = ip
			} else if ids, ok := base["identifiers"].(map[string]interface{}); ok {
				if net, ok := ids["network"].(map[string]interface{}); ok {
					la.DstIP, _ = net["dstIP"].(string)
				}
			}

			// Port
			switch p := args["port"].(type) {
			case float64:
				la.Port = fmt.Sprintf("%d", int(p))
			case string:
				la.Port = p
			}

			// Addresses (DNS)
			if addrs, ok := args["addresses"].([]interface{}); ok {
				for _, a := range addrs {
					if s, ok := a.(string); ok {
						la.Addresses = append(la.Addresses, s)
					}
				}
			}
		}

		alerts = append(alerts, la)
	}
	return alerts
}

// FilterLogAlerts returns alerts matching the given rule ID.
func FilterLogAlerts(alerts []LogAlert, ruleID string) []LogAlert {
	var out []LogAlert
	for _, a := range alerts {
		if a.RuleID == ruleID {
			out = append(out, a)
		}
	}
	return out
}

// LogAlertDomains returns unique domain values from a set of log alerts.
func LogAlertDomains(alerts []LogAlert) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range alerts {
		if a.Domain != "" && !seen[a.Domain] {
			seen[a.Domain] = true
			out = append(out, a.Domain)
		}
	}
	return out
}

// LogAlertIPs returns unique DstIP values from a set of log alerts.
func LogAlertIPs(alerts []LogAlert) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range alerts {
		if a.DstIP != "" && !seen[a.DstIP] {
			seen[a.DstIP] = true
			out = append(out, a.DstIP)
		}
	}
	return out
}
