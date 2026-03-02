package model

// LangString represents a language-tagged string value, commonly used
// for CVE descriptions that may be provided in multiple languages.
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// English returns the first English-language string from a slice,
// falling back to the first entry if no English string is found.
func English(ls []LangString) string {
	for _, s := range ls {
		if s.Lang == "en" {
			return s.Value
		}
	}
	if len(ls) > 0 {
		return ls[0].Value
	}
	return ""
}
