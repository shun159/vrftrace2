module github.com/shun159/vrftrace2

go 1.18

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/apache/thrift v0.16.0 // indirect
	github.com/aquasecurity/libbpfgo v0.2.5-libbpf-0.7.0.0.20220503131840-80f44303d40f // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/josharian/native v0.0.0-20200817173448-b6b71def0850 // indirect
	github.com/mdlayher/genetlink v1.1.0 // indirect
	github.com/mdlayher/netlink v1.5.0 // indirect
	github.com/mdlayher/socket v0.1.0 // indirect
	github.com/shun159/vr v0.0.0-20220430075319-d65bbaf9cd8d // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	github.com/zcalusic/sysinfo v0.9.5 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/net v0.0.0-20211209124913-491a49abca63 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220503163025-988cb79eb6c6 // indirect
	golang.org/x/tools v0.1.8 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	honnef.co/go/tools v0.2.2 // indirect
)

require internal/vrft v0.0.0

replace internal/vrft => ./internal/vrft
