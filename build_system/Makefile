
DOT = dot
LATEX = latex
DVIPDF = dvipdf

png = mk.relation.png
pdf = mk.detail.pdf
all:$(png) $(pdf)

%.png:%.dot
	$(DOT) -Tpng -o $@ $^
%.pdf:%.dvi
	$(DVIPDF) $^
%.dvi:%.tex
	$(LATEX) $^

.PHONY:clean
clean:
	$(RM) $(png)
	$(RM) $(pdf)
	$(RM) *.log *.aux *.toc

