# trace_open is vendored (not pulled from upstream IG) so the fpath resolver can
# resolve relative opens against their dirfd/cwd -- see program.bpf.c. Built under
# the same image name node-agent already pins in open.go, so nothing else changes.
IMAGE?=ghcr.io/inspektor-gadget/gadget/trace_open
TAG?=v0.48.1

# Pin the builder to the v0.48.1 default so the vendored source (authored against
# v0.48.1 gadget headers) compiles the same way regardless of which ig CLI the
# caller has installed. A newer builder's gadget_get_user_stack macro rejects the
# v0.48.1 syscall_trace_exit ctx type; pinning keeps the build reproducible.
BUILDER_IMAGE?=ghcr.io/inspektor-gadget/gadget-builder@sha256:e0e88543a99bbc4b1263b7f9d07a08fb8f1107426525ef8b777bdd8df15d1ee8

build:
	sudo TMPDIR=$$TMPDIR ig image build -t $(IMAGE):$(TAG) . --update-metadata --builder-image $(BUILDER_IMAGE)

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run
