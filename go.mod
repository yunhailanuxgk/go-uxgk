module github.com/yunhailanuxgk/go-uxgk

go 1.13

require (
	bazil.org/fuse v0.0.0-20200117225306-7b5117fecadc
	github.com/aristanetworks/goarista v0.0.0-20200224203130-895b4c57c44d
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/cc14514/go-alibp2p v0.0.0-00010101000000-000000000000
	github.com/cc14514/go-uxgklib v0.0.0-00010101000000-000000000000
	github.com/cespare/cp v1.1.1
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/docker v1.13.1
	github.com/edsrzf/mmap-go v1.0.0
	github.com/emicklei/proto v1.9.0 // indirect
	github.com/fatih/color v1.9.0
	github.com/go-stack/stack v1.8.0
	github.com/gobuffalo/flect v0.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/mock v1.4.0 // indirect
	github.com/golang/protobuf v1.3.3
	github.com/golang/snappy v0.0.1
	github.com/golangci/golangci-lint v1.23.1 // indirect
	github.com/google/keytransparency v0.1.3
	github.com/google/trillian v1.3.3
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.13.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/huandu/xstrings v1.3.0 // indirect
	github.com/huin/goupnp v1.0.0
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/jhump/protoreflect v1.6.0 // indirect
	github.com/jirfag/go-printf-func-name v0.0.0-20200119135958-7558a9eaa5af // indirect
	github.com/julienschmidt/httprouter v1.3.0
	github.com/karalabe/hid v1.0.0
	github.com/mattn/go-colorable v0.1.4
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mattn/go-runewidth v0.0.8 // indirect
	github.com/mwitkow/go-proto-validators v0.3.0 // indirect
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/naoina/toml v0.1.2-0.20170918210437-9fafd6967416
	github.com/olekukonko/tablewriter v0.0.4
	github.com/pborman/uuid v1.2.0
	github.com/peterh/liner v1.2.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.4.1 // indirect
	github.com/rakyll/statik v0.1.7
	github.com/rcrowley/go-metrics v0.0.0-20190826022208-cac0b30c2563
	github.com/rjeczalik/notify v0.9.2
	github.com/robertkrimen/otto v0.0.0-20191219234010-c382bd3c16ff
	github.com/rs/cors v1.7.0
	github.com/securego/gosec v0.0.0-20200121091311-459e2d3e91bd // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v0.0.6 // indirect
	github.com/spf13/viper v1.6.2 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/goleveldb v1.0.1-0.20190923125748-758128399b1d
	github.com/urfave/cli v1.22.2 // indirect
	go.etcd.io/etcd v3.3.18+incompatible // indirect
	go.opencensus.io v0.22.3 // indirect
	golang.org/x/crypto v0.0.0-20200221231518-2aa609cf4a9d
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/mod v0.2.0 // indirect
	golang.org/x/net v0.0.0-20200225223329-5d076fcf07a8
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	golang.org/x/tools v0.0.0-20200225230052-807dcd883420
	google.golang.org/genproto v0.0.0-20200225123651-fc8f55426688 // indirect
	google.golang.org/grpc v1.27.1 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/fatih/set.v0 v0.2.1
	gopkg.in/ini.v1 v1.51.1 // indirect
	gopkg.in/karalabe/cookiejar.v2 v2.0.0-20150724131613-8dcd6a7f4951
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20190709231704-1e4459ed25ff
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace github.com/cc14514/go-uxgklib => ../go-uxgklib

replace github.com/cc14514/go-alibp2p => ../go-alibp2p

replace github.com/libp2p/go-libp2p-kad-dht => github.com/cc14514/go-libp2p-kad-dht v0.0.0-20191107040323-2463a62af156

replace github.com/libp2p/go-libp2p => github.com/cc14514/go-libp2p v0.0.0-20200118065341-58abd62e1061

replace github.com/libp2p/go-libp2p-swarm => github.com/cc14514/go-libp2p-swarm v0.0.0-20200118064831-601363b81fc2

replace github.com/libp2p/go-libp2p-circuit => github.com/cc14514/go-libp2p-circuit v0.0.0-20191111122236-413fc41ad3d7
