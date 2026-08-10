package cloudmetadata

import (
	"context"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	k8sInterfaceCloudMetadata "github.com/kubescape/k8s-interface/cloudmetadata"
	"github.com/kubescape/k8s-interface/k8sinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetCloudMetadata retrieves cloud metadata for a given node
func GetCloudMetadata(ctx context.Context, client *k8sinterface.KubernetesApi, nodeName string) (*armotypes.CloudMetadata, error) {
	node, err := client.GetKubernetesClient().CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeName, err)
	}

	cMetadata, err := k8sInterfaceCloudMetadata.GetCloudMetadata(ctx, node, nodeName)
	if err != nil {
		return nil, err
	}

	// special case for AWS, if the account ID is not found in the node metadata, we need to get it from ConfigMap
	enrichCloudMetadataForAWS(ctx, client, cMetadata)
	// special case for Azure, enrich ResourceGroup from node providerID
	enrichCloudMetadataForAzure(node, cMetadata)
	return cMetadata, nil
}

func enrichCloudMetadataForAWS(ctx context.Context, client *k8sinterface.KubernetesApi, cMetadata *armotypes.CloudMetadata) {
	if cMetadata == nil || cMetadata.Provider != armotypes.ProviderAws || cMetadata.AccountID != "" {
		return
	}

	cm, err := client.GetKubernetesClient().CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if err != nil {
		logger.L().Warning("failed to get aws-auth ConfigMap", helpers.Error(err))
		return
	}

	err = k8sInterfaceCloudMetadata.EnrichCloudMetadataFromAWSAuthConfigMap(cMetadata, cm)
	if err != nil {
		logger.L().Warning("failed to enrich cloud metadata from aws-auth ConfigMap", helpers.Error(err))
	}

	logger.L().Debug("enriched cloud metadata from aws-auth ConfigMap")
}

func enrichCloudMetadataForAzure(node *corev1.Node, cMetadata *armotypes.CloudMetadata) {
	if cMetadata == nil || cMetadata.Provider != armotypes.ProviderAzure || cMetadata.ResourceGroup != "" {
		return
	}

	// Parse ResourceGroup from node's providerID
	// Format: azure:///subscriptions/{sub}/resourceGroups/{rg}/providers/...
	providerID := node.Spec.ProviderID
	if rg := parseAzureResourceGroup(providerID); rg != "" {
		cMetadata.ResourceGroup = rg
		logger.L().Debug("enriched cloud metadata with Azure ResourceGroup from node providerID", helpers.String("resourceGroup", rg))
	}
}

func parseAzureResourceGroup(providerID string) string {
	// providerID format: azure:///subscriptions/.../resourceGroups/{resourceGroup}/providers/...
	const marker = "/resourceGroups/"
	idx := strings.Index(strings.ToLower(providerID), strings.ToLower(marker))
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	rest := providerID[start:]
	end := strings.Index(rest, "/")
	if end == -1 {
		return rest
	}
	return rest[:end]
}
