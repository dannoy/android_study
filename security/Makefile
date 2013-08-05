
DOT = dot
LATEX = latex
DVIPDF = dvipdf

#png = mk.relation.png
#ps = dot/driver_data_structure.ps
pdf = android_security_analysis.pdf
all:$(png) $(pdf) $(ps)

inner.tex:android_security_analysis.md
	pandoc -o $@ $^

%.png:%.dot
	$(DOT) -Tpng -o $@ $^
%.ps:%.dot
	$(DOT) -Tps -o $@ $^
%.pdf:%.dvi
	$(DVIPDF)  $^
%.dvi:%.tex inner.tex
	$(LATEX) $^

#$(pdf)::$(ps);
.PHONY:clean
clean:
	$(RM) $(png)
	$(RM) $(pdf)
	$(RM) *.log *.aux *.toc *.out inner.tex
