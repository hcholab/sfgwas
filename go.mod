module github.com/hcholab/sfgwas

go 1.21

require (
	github.com/BurntSushi/toml v1.2.1
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/hhcho/frand v1.3.1-0.20210217213629-f1c60c334950
	github.com/hhcho/mpc-core v0.0.0-20220828210829-24cf7abd1073
	github.com/ldsec/lattigo/v2 v2.4.0
	github.com/ldsec/unlynx v1.4.3
	github.com/raulk/go-watchdog v1.3.0
	go.dedis.ch/onet/v3 v3.2.10
	golang.org/x/net v0.23.0
	gonum.org/v1/gonum v0.12.0
)

replace go.dedis.ch/onet/v3 => github.com/hcholab/onet/v3 v3.0.0-20230828232509-90c2e1097481

require (
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/daviddengcn/go-colortext v1.0.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/fanliao/go-concurrentMap v0.0.0-20141114143905-7d2d7a5ea67b // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smartystreets/assertions v1.13.1 // indirect
	github.com/stretchr/testify v1.8.2 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/kyber/v3 v3.1.0 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	go.etcd.io/bbolt v1.3.8 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20230425010034-47ecfdc1ba53 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	rsc.io/goversion v1.2.0 // indirect
)

replace github.com/ldsec/lattigo/v2 => github.com/hcholab/lattigo/v2 v2.1.2-0.20220628190737-bde274261547
