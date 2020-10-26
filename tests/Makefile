# Useful automatic variables:
# 	$@ - The name of the target of the rule
# 	$* - The stem of the pattern (%)
# 	$< - The name of the first prerequisite
# 	$^ - The name of all the prerequisites
MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:

VANILLA_TRACES := data/vanilla-shaped.csv data/vanilla-unshaped.csv data/vanilla-tcp.csv
TSO_DISABLE_IFACE := lo


all: $(VANILLA_TRACES)


data/vanilla-shaped.pcapng: 
	inv collect-quic --shaping $@ 

data/vanilla-unshaped.pcapng:
	inv collect-quic --no-shaping $@ 

data/vanilla-tcp.pcapng: /tmp/iface-configured
	inv collect-tcp $@ 

/tmp/iface-configured:
	# We need the MTU of the loopback to resemble the "typical" network since
	# our webserver runs on the loopback interface
	sudo ip link set dev $(TSO_DISABLE_IFACE) mtu 1500
	# Disable TCP offloading which would make the packets look bigger
	sudo ethtool -K $(TSO_DISABLE_IFACE) gso off gro off tso off

	touch $@

%.csv: %.pcapng
	inv -r "../python" pcap-to-csv $< > $@
