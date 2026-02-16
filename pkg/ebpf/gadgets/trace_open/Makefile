IMAGE?=trace_open
TAG?=latest

build:
	sudo TMPDIR=$$TMPDIR ig image build -t $(IMAGE):$(TAG) .

run:
	sudo ig run $(IMAGE):$(TAG) --verify-image=false -o jsonpretty

build-and-run: build run