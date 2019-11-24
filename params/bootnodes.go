// Copyright 2015 The UXGK Authors
// This file is part of the UXGK library.
//
// The UXGK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The UXGK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the UXGK library. If not, see <http://www.gnu.org/licenses/>.

package params

var MainnetBootnodes = []string{
	"/ip4/47.56.144.168/tcp/30403/ipfs/16Uiu2HAmKNPuWPPJZomFFKA2gqwjbcThf7PihRrsXMQmPS1PusDp",
}

var TestnetBootnodes = []string{
	//"enode://85ef2a2cb3e822c5c0db745fd442f8c93038cbb184ed3b0778dd976a2f50f8929e6bf084c36d8ba80b4ba735ef19957dd6cb54b7a3d8012b467fd2cc1e492a3c@101.251.230.212:30403",
	"/ip4/101.251.230.212/tcp/30403/ipfs/16Uiu2HAmHPj9yEaDgut5Sp9URGDoaHNbUrCX67cppsy2r2NipUMu",
}

var DevnetBootnodes = []string{
}

var RinkebyBootnodes = []string{}

var RinkebyV5Bootnodes = []string{}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
