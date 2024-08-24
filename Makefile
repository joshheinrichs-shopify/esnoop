CC ?= clang

.PHONY: default
default: esnoop

esnoop: esnoop.c esnoop.entitlements
	$(CC) -o esnoop esnoop.c -framework Foundation -lbsm -lEndpointSecurity
	codesign --sign - --entitlements esnoop.entitlements --deep esnoop --force

.PHONY: clean
clean:
	rm esnoop
