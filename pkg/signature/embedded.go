package signature

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

// encodeEmbeddedContent packs canonical content bytes for the
// AnnotationContent annotation: base64(gzip(bytes)).
func encodeEmbeddedContent(content []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(content); err != nil {
		return "", fmt.Errorf("gzip embedded content: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// decodeEmbeddedContent unpacks an AnnotationContent value.
func decodeEmbeddedContent(encoded string) ([]byte, error) {
	gz, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64-decode embedded content: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("gunzip embedded content: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("read embedded content: %w", err)
	}
	return out, nil
}

// EmbeddedContent returns the canonical signed content embedded in the
// object's annotations, if present. When present, the signature was computed
// over exactly these bytes and they are the verified source of truth — the
// object's own spec may have been normalised by the server since.
func EmbeddedContent(obj SignableObject) ([]byte, bool, error) {
	if obj == nil {
		return nil, false, fmt.Errorf("nil object")
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return nil, false, nil
	}
	enc, ok := annotations[AnnotationContent]
	if !ok {
		return nil, false, nil
	}
	content, err := decodeEmbeddedContent(enc)
	if err != nil {
		return nil, true, err
	}
	return content, true, nil
}
