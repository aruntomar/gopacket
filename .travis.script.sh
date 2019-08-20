#!/bin/bash

set -ev

go test github.com/aruntomar/gopacket
go test github.com/aruntomar/gopacket/layers
go test github.com/aruntomar/gopacket/tcpassembly
go test github.com/aruntomar/gopacket/reassembly
go test github.com/aruntomar/gopacket/pcapgo 
go test github.com/aruntomar/gopacket/pcap
