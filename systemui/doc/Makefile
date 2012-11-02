
DOT = dot
LATEX = latex
DVIPDF = dvipdf

#png = mk.relation.png
#ps = dot/driver_data_structure.ps
pdf = systemui.pdf
all:$(png) $(pdf) $(ps)

%.png:%.dot
	$(DOT) -Tpng -o $@ $^
%.ps:%.dot
	$(DOT) -Tps -o $@ $^
%.pdf:%.dvi
	$(DVIPDF)  $^
%.dvi:%.tex
	$(LATEX) $^

#$(pdf)::$(ps);
.PHONY:clean
clean:
	$(RM) $(png)
	$(RM) $(pdf)
	$(RM) *.log *.aux *.toc
