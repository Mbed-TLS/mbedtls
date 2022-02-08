# If we are the top level Makefile, call the one in the root dir instead
.SILENT:
.PHONY: all
all:
	$(MAKE) -C .. $(patsubst %,tests/%,$(or $(MAKECMDGOALS),all))

$(filter-out all,$(MAKECMDGOALS)): all
