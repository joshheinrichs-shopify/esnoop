# esnoop

endpoint security no-op to assess endpoint security's[^1] overhead.

## usage

currently requires SIP to be disabled. easiest way to do that is:

1. install UTM via `brew install --cask utm`[^2]
1. create a macOS VM
1. stop the VM
1. disable SIP by starting the VM in recovery mode, open a terminal, and running `csrutil disable`[^3]
1. restart the VM

after that you can clone this repo and build and run `esnoop`.

[^1]: https://developer.apple.com/documentation/endpointsecurity
[^2]: https://formulae.brew.sh/cask/utm
[^3]: https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection
