ifndef SDE
$(error SDE is not defined)
endif

ifndef SDE_INSTALL
$(error SDE_INSTALL is not defined)
endif

SRC := p4src
INCLUDE := $(${SRC}/include/*.p4)
P4FLAGS := "-g --verbose 2"

.PHONY: all
all: scitra_tf1 # scitra_tf2

.PHONY: clean
clean:
	rm -rf build

.PHONY: scitra_tf1
scitra_tf1: ${SRC}/scitra.p4 build/scitra_tf1/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

.PHONY: scitra_tf2
scitra_tf2: ${SRC}/scitra.p4 build/scitra_tf2/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

build/%_tf1/Makefile: ${SRC}/%.p4
	cmake ${SDE}/p4studio -B build/$*_tf1 \
		-DCMAKE_MODULE_PATH=${SDE}/cmake \
		-DCMAKE_INSTALL_PREFIX="${SDE_INSTALL}" \
		-DP4_PATH="$(realpath $<)" \
		-DP4_NAME="$(basename $(nodir $<))" \
		-DP4_LANG=p4-16 \
		-DTOFINO2=OFF \
		-DP4FLAGS=${P4FLAGS}

build/%_tf2/Makefile: ${SRC}/%.p4
	cmake ${SDE}/p4studio -B build/$*_tf2 \
		-DCMAKE_MODULE_PATH=${SDE}/cmake \
		-DCMAKE_INSTALL_PREFIX="${SDE_INSTALL}" \
		-DP4_PATH="$(realpath $<)" \
		-DP4_NAME="$(basename $(nodir $<))" \
		-DP4_LANG=p4-16 \
		-DTOFINO2=ON \
		-DP4FLAGS=${P4FLAGS}

${SRC}/scitra.p4: ${INCLUDE}
	@touch $@
