SRC := p4src
INCLUDE := ${SRC}/include/aes.p4 ${SRC}/include/parser.p4
P4FLAGS := "-g --verbose 2"

include ../Makefile.inc

.PHONY: all
all: aes_tf1 aes_tf1_test

.PHONY: clean
clean:
	rm -rf build

.PHONY: aes_tf1
aes_tf1: ${SRC}/aes_tf1.p4 build/aes_tf1/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_tf1.p4: ${INCLUDE}
	@touch $@

.PHONY: aes_tf1_test
aes_tf1_test: ${SRC}/aes_tf1_test.p4 build/aes_tf1_test/Makefile
	$(MAKE) -C build/$@ && $(MAKE) -C build/$@ install

${SRC}/aes_tf1_test.p4: ${INCLUDE}
	@touch $@
