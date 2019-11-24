// Copyright 2017 The UXGK Authors
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

package core

// Constants containing the genesis allocation of built-in genesis blocks.
// Their content is an RLP-encoded list of (address, balance) tuples.
// Use mkalloc.go to create/update them.

// nolint: misspell
const mainnetAllocData = "\xf8B\xe2\x94\x17D#\x93\u07e4\xc0][>\xf9&5=\xa8\x14\x93\a\xdb\xea\x8c\x10'\xe7/\x1f\x12\x810\x88\x00\x00\x00\u0794\xd0J\xe6\x17.R\r\x0et\xaf5\xaa\x84\xbdUK\xe7\xc1\xc8\t\x88Ec\x91\x82D\xf4\x00\x00"

const testnetAllocData = "\xe6\xe5\x94s\xb4\x8fs?\xfcd`\xb9n\xff\xb7|\xd8}=\xb5\x81>\x82\x8f\x01\xed\t\xbe\xad\x87\xc07\x8d\x8ed\x00\x00\x00\x00"

const devnetAllocData = "\xf8F\u253f\x176\xa6_\x8b\xea\xddq\xb3!\xbeX_\u0603P?\u07aa\x8c\x10'\xe7/\x1f\x12\x810\x88\x00\x00\x00\xe2\x94\u04f3\x84x\xf7\xed\xb9\xbbU'\x0e\xe58\x97\x06\u071c\xa6\u064f\x8c\x10'\xe7/\x1f\x12\x810\x88\x00\x00\x00"
