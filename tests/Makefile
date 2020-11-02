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

VANILLA_TRACES := data/vanilla-shaped.csv data/vanilla-unshaped.csv # data/vanilla-tcp.csv
TSO_DISABLE_IFACE := lo
TSO_DISABLE_IFACE_MACOS := lo0

UNAME_S := $(uname -s) # OS name


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
	ifeq ($(UNAME_S),Darwin) # macOS case does not have ip
		sudo ifconfig $(TSO_DISABLE_IFACE_MACOS) mtu 1500
	else
		sudo ip link set dev $(TSO_DISABLE_IFACE) mtu 1500
	endif
	# Disable TCP offloading which would make the packets look bigger
	sudo ethtool -K $(TSO_DISABLE_IFACE) gso off gro off tso off
	# TODO: ethtool does not exists on macos

	touch $@

%.csv: %.pcapng
	inv -r "../python" pcap-to-csv $< > $@
