# trace_open is vendored (not pulled from upstream IG) so the fpath resolver can
# resolve relative opens against their dirfd/cwd — see program.bpf.c. Built under
# the same image name node-agent already pins in open.go, so nothing else changes.
IMAGE?=ghcr.io/inspektor-gadget/gadget/trace_open
TAG?=v0.48.1

build:
	sudo TMPDIR=$$TMPDIR ig image build -t $(IMAGE):$(TAG) . --update-metadata

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run
