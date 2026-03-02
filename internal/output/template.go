package output

import (
	"io"
	"text/template"

	"github.com/trustin-tech/vulnex/internal/cache"
	"github.com/trustin-tech/vulnex/internal/model"
)

type templateFormatter struct {
	tmplStr string
}

func newTemplateFormatter(tmpl string) *templateFormatter {
	return &templateFormatter{tmplStr: tmpl}
}

func (f *templateFormatter) FormatCVE(w io.Writer, cve *model.EnrichedCVE) error {
	tmpl, err := template.New("cve").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, cve)
}

func (f *templateFormatter) FormatCVEList(w io.Writer, cves []*model.EnrichedCVE) error {
	tmpl, err := template.New("cves").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	for _, cve := range cves {
		if cve == nil {
			continue
		}
		if err := tmpl.Execute(w, cve); err != nil {
			return err
		}
	}
	return nil
}

func (f *templateFormatter) FormatKEVList(w io.Writer, entries []model.KEVEntry) error {
	tmpl, err := template.New("kev").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := tmpl.Execute(w, e); err != nil {
			return err
		}
	}
	return nil
}

func (f *templateFormatter) FormatEPSSScores(w io.Writer, scores map[string]*model.EPSSScore) error {
	tmpl, err := template.New("epss").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	for id, s := range scores {
		data := map[string]interface{}{
			"ID":    id,
			"Score": s,
		}
		if err := tmpl.Execute(w, data); err != nil {
			return err
		}
	}
	return nil
}

func (f *templateFormatter) FormatAdvisory(w io.Writer, advisory *model.EnrichedAdvisory) error {
	tmpl, err := template.New("advisory").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, advisory)
}

func (f *templateFormatter) FormatAdvisories(w io.Writer, advisories []model.Advisory) error {
	tmpl, err := template.New("advisory").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	for _, a := range advisories {
		if err := tmpl.Execute(w, a); err != nil {
			return err
		}
	}
	return nil
}

func (f *templateFormatter) FormatCacheStats(w io.Writer, stats *cache.Stats) error {
	tmpl, err := template.New("stats").Parse(f.tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, stats)
}
