PANDOC = pandoc

default: all

all_markdown = $(wildcard *.md)

html: $(all_markdown:.md=.html)
	$(MAKE) -C architecture html
	$(MAKE) -C proposed html

pdf: $(all_markdown:.md=.pdf)
	$(MAKE) -C architecture pdf
	$(MAKE) -C proposed pdf

all: html pdf

.SUFFIXES:
.SUFFIXES: .md .html .pdf

.md.html:
	$(PANDOC) -o $@ $<
.md.pdf:
	$(PANDOC) -o $@ $<

clean:
	rm -f *.html *.pdf
	$(MAKE) -C architecture clean
	$(MAKE) -C proposed clean
