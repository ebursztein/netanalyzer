#
# netprof - dummy makefile
# --------------------
#
# Just for convenience.
# 
# inspired by the makefile system of Michal Zalewski <lcamtuf@coredump.cx>
# (C) Copyright 2004  by Elie Bursztein <elie@bursztein.net>

regular:
	./Build $@
tcpdump:
	./Build regular 
debug:
	./Build regular 
all: 
	./Build $@

static: 
	./Build $@

clean:
	./Build $@

makedist:
	./Build $@

install:
	./Build $@

