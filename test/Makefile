VERSION = 0.30
DIST_STAGING = globus_connect_server_test-$(VERSION)
DIST_FILE = $(DIST_STAGING).tar.gz

osname := $(shell lsb_release -is)
osver  := $(shell lsb_release -rs)

ifeq(,$(osname)$(osver))
    test_endpoint_suffix =
else
    test_endpoint_suffix = $(osname)_$(osver)
endif

test:
	env GLOBUS_USER=gcmutest \
            GLOBUS_PASSWORD=Automatic-GCMU-Test-Cases \
	    TEST_ENDPOINT_SUFFIX=$(test_endpoint_suffix) \
            TERM=vt100 \
            perl TESTS-junit.pl || true

multinode-test:
	if test $(BARRIER_URL) = ''; then \
            exit 1; \
        else \
            env GLOBUS_USER=gcmutest \
                GLOBUS_PASSWORD=Automatic-GCMU-Test-Cases \
                TERM=vt100 \
                perl TESTS-multinode-junit.pl || true ; \
	fi


dist:
	rm -rf $(DIST_STAGING)
	mkdir $(DIST_STAGING)
	cp Makefile *.conf *.pl *.pm *.py *.css *.png tap-to-junit-xml $(DIST_STAGING)
	tar -c -f - $(DIST_STAGING) | gzip -9c > $(DIST_FILE)
	rm -rf $(DIST_STAGING)

distname:
	@echo $(DIST_FILE)
distclean:
	rm *.xml

.PHONY: dist distclean test
