# -*- Makefile -*-

# --------------------------------------------------------------------
version    ?= 0.7.0
name        = miTLS
distname    = $(name)-$(version)
f7distname  = $(name)-f7-$(version)

TAR = tar --format=posix --owner=0 --group=0

include Makefile.config

.PHONY: all build build-debug make.in prepare-dist
.PHONY: do-dist-check dist dist-check

# --------------------------------------------------------------------
all: build

build = $(msbuild) /p:Configuration=$(1) tls.sln
clean = $(msbuild) /v:minimal /p:Configuration=$(1) /t:Clean tls.sln

build:
	$(call build,Release)

build-debug:
	$(call build,Debug)

clean:
	$(call clean,Release)
	$(call clean,Debug)

dist-clean: clean
	rm -f $(distname).tgz
	rm -f $(f7distname).tgz

# --------------------------------------------------------------------
prepare-dist:
	rm -rf $(distname) && mkdir $(distname)
	rm -rf $(distname).tgz
	scripts/distribution $(distname) MANIFEST
	find $(distname) \( -type f -a \! -name '*.dll' \) -exec chmod a-x '{}' \+	
	chmod a+x $(distname)/scripts/*

dist: prepare-dist
	if [ -x scripts/anonymize ]; then \
	  find $(distname) \
	    -type f \( -name '*.fs' -o -name '*.fsi' -o -name '*.fs7' \) \
	    -exec scripts/anonymize \
	      -m release -B -P -I wsgi -I ideal -I verify -I optimize_bytes \
	      -c LICENSE.header '{}' \+; \
	fi
	$(TAR) -czf $(distname).tgz $(distname)
	rm -rf $(distname)

do-dist-check:
	tar -xof $(distname).tgz
	set -x; \
	     $(MAKE) -C $(distname) \
	  && $(MAKE) -C $(distname) dist \
	  && mkdir $(distname)/dist1 $(distname)/dist2 \
	  && ( cd $(distname)/dist1 && tar -xof ../$(distname).tgz ) \
	  && ( cd $(distname)/dist2 && tar -xof ../../$(distname).tgz ) \
	  && diff -rq $(distname)/dist1 $(distname)/dist2 \
	  || exit 1
	rm -rf $(distname)
	@echo "$(distname).tgz is ready for distribution" | \
	  sed -e 1h -e 1s/./=/g -e 1p -e 1x -e '$$p' -e '$$x'

dist-check: dist do-dist-check
