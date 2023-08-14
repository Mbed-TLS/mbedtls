PANDOC = pandoc

default: all

all_markdown = \
               alternative-implementations.md \
               mbed-crypto-storage-specification.md \
               psa-crypto-implementation-structure.md \
               psa-migration/psa-limitations.md \
               psa-migration/strategy.md \
               psa-migration/tasks-g2.md \
               psa-migration/testing.md \
               testing/driver-interface-test-strategy.md \
               testing/invasive-testing.md \
               testing/psa-storage-format-testing.md \
               testing/test-framework.md \
               tls13-support.md \
	       # This line is intentionally left blank

html: $(all_markdown:.md=.html)
pdf: $(all_markdown:.md=.pdf)
all: html pdf

.SUFFIXES:
.SUFFIXES: .md .html .pdf

.md.html:
	$(PANDOC) -o $@ $<
.md.pdf:
	$(PANDOC) -o $@ $<

clean:
	rm -f *.html *.pdf
	rm -f testing/*.html testing/*.pdf
