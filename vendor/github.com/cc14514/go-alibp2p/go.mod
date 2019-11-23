module github.com/cc14514/go-alibp2p

require (
	github.com/btcsuite/btcd v0.0.0-20190213025234-306aecffea32
	github.com/cc14514/go-mux-transport v0.0.0-20191107033455-2e89816349e6
	github.com/hashicorp/golang-lru v0.5.1
	github.com/libp2p/go-buffer-pool v0.0.2
	github.com/libp2p/go-libp2p v0.1.0
	github.com/libp2p/go-libp2p-circuit v0.1.0
	github.com/libp2p/go-libp2p-connmgr v0.1.0
	github.com/libp2p/go-libp2p-core v0.0.1
	github.com/libp2p/go-libp2p-kad-dht v0.1.0
	github.com/libp2p/go-libp2p-mplex v0.2.1
	github.com/libp2p/go-libp2p-pnet v0.1.0
	github.com/libp2p/go-libp2p-yamux v0.2.0
	github.com/multiformats/go-multiaddr v0.0.4
	github.com/stretchr/testify v1.4.0 // indirect
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)

go 1.13

replace github.com/libp2p/go-libp2p-swarm => github.com/cc14514/go-libp2p-swarm v0.0.0-20191111121429-bf40e092865b

replace github.com/libp2p/go-libp2p-kad-dht => github.com/cc14514/go-libp2p-kad-dht v0.0.0-20191107040323-2463a62af156

replace github.com/libp2p/go-libp2p => github.com/cc14514/go-libp2p v0.0.0-20191107035444-bf2343196cca

replace github.com/libp2p/go-libp2p-circuit => github.com/cc14514/go-libp2p-circuit v0.0.0-20191111122236-413fc41ad3d7
