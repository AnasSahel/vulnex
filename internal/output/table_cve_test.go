package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/trustin-tech/vulnex/internal/model"
)

func newTestTableFormatter(long bool) *tableFormatter {
	return newTableFormatter(&formatterOpts{NoColor: true, Long: long})
}

func TestFormatCVE_LastModified(t *testing.T) {
	tf := newTestTableFormatter(false)
	cve := &model.EnrichedCVE{
		ID:           "CVE-2021-44228",
		Published:    time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		LastModified: time.Date(2023, 11, 6, 0, 0, 0, 0, time.UTC),
		CVSS: []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Last Modified:") {
		t.Error("expected Last Modified field in output")
	}
	if !strings.Contains(out, "2023-11-06") {
		t.Error("expected last modified date 2023-11-06")
	}
}

func TestFormatCVE_LastModifiedSameAsPublished(t *testing.T) {
	tf := newTestTableFormatter(false)
	published := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	cve := &model.EnrichedCVE{
		ID:           "CVE-2021-44228",
		Published:    published,
		LastModified: published,
		CVSS: []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(buf.String(), "Last Modified:") {
		t.Error("Last Modified should not appear when same as Published")
	}
}

func TestFormatCVE_AffectedVersions(t *testing.T) {
	tf := newTestTableFormatter(false)
	cve := &model.EnrichedCVE{
		ID:        "CVE-2021-44228",
		Published: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		CVSS:      []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
		CPEs: []model.CPEMatch{
			{
				CPE23URI:       "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
				Vulnerable:     true,
				VersionStartIncl: "2.0",
				VersionEndExcl:   "2.15.0",
			},
		},
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Affected Versions") {
		t.Error("expected Affected Versions section")
	}
	if !strings.Contains(out, "apache:log4j") {
		t.Error("expected product name apache:log4j")
	}
	if !strings.Contains(out, ">= 2.0") {
		t.Error("expected version start >= 2.0")
	}
	if !strings.Contains(out, "< 2.15.0") {
		t.Error("expected version end < 2.15.0")
	}
}

func TestFormatCVE_References(t *testing.T) {
	tf := newTestTableFormatter(false)
	cve := &model.EnrichedCVE{
		ID:        "CVE-2021-44228",
		Published: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		CVSS:      []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
		References: []model.Reference{
			{URL: "https://example.com/patch", Tags: []string{"Patch"}},
			{URL: "https://example.com/advisory", Tags: []string{"Vendor Advisory"}},
			{URL: "https://example.com/exploit", Tags: []string{"Exploit"}},
		},
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "References") {
		t.Error("expected References section")
	}
	if !strings.Contains(out, "https://example.com/patch") {
		t.Error("expected patch reference URL")
	}
	if !strings.Contains(out, "[Patch]") {
		t.Error("expected Patch tag")
	}
}

func TestFormatCVE_ReferencesLimitedInShortMode(t *testing.T) {
	tf := newTestTableFormatter(false)
	refs := make([]model.Reference, 8)
	for i := range refs {
		refs[i] = model.Reference{URL: "https://example.com/" + string(rune('a'+i))}
	}

	cve := &model.EnrichedCVE{
		ID:         "CVE-2021-44228",
		Published:  time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		CVSS:       []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
		References: refs,
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "(3 more...)") {
		t.Error("expected '(3 more...)' indicator for truncated references")
	}
}

func TestFormatCVE_ReferencesAllShownInLongMode(t *testing.T) {
	tf := newTestTableFormatter(true)
	refs := make([]model.Reference, 8)
	for i := range refs {
		refs[i] = model.Reference{URL: "https://example.com/" + string(rune('a'+i))}
	}

	cve := &model.EnrichedCVE{
		ID:         "CVE-2021-44228",
		Published:  time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		CVSS:       []model.CVSSScore{{BaseScore: 10.0, Version: "3.1", Severity: "CRITICAL"}},
		References: refs,
	}

	var buf bytes.Buffer
	if err := tf.FormatCVE(&buf, cve); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "more...") {
		t.Error("long mode should show all references without truncation")
	}
	// All 8 URLs should be present
	for i := 0; i < 8; i++ {
		url := "https://example.com/" + string(rune('a'+i))
		if !strings.Contains(out, url) {
			t.Errorf("expected URL %s in long mode output", url)
		}
	}
}

func TestCpeProduct(t *testing.T) {
	tests := []struct {
		cpe23 string
		want  string
	}{
		{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "apache:log4j"},
		{"cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*", "microsoft:windows_10"},
		{"short", "short"},
	}
	for _, tt := range tests {
		got := cpeProduct(tt.cpe23)
		if got != tt.want {
			t.Errorf("cpeProduct(%q) = %q, want %q", tt.cpe23, got, tt.want)
		}
	}
}

func TestCpeVersionRange(t *testing.T) {
	tests := []struct {
		name string
		cpe  model.CPEMatch
		want string
	}{
		{
			name: "inclusive range",
			cpe:  model.CPEMatch{VersionStartIncl: "2.0", VersionEndIncl: "2.14.1"},
			want: ">= 2.0, <= 2.14.1",
		},
		{
			name: "exclusive range",
			cpe:  model.CPEMatch{VersionStartIncl: "2.0", VersionEndExcl: "2.15.0"},
			want: ">= 2.0, < 2.15.0",
		},
		{
			name: "specific version from CPE",
			cpe:  model.CPEMatch{CPE23URI: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
			want: "2.0",
		},
		{
			name: "all versions",
			cpe:  model.CPEMatch{CPE23URI: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
			want: "all versions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cpeVersionRange(tt.cpe)
			if got != tt.want {
				t.Errorf("cpeVersionRange() = %q, want %q", got, tt.want)
			}
		})
	}
}
