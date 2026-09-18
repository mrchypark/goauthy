package branding

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestSanitizedLogoSVGPreservesPinnedGraphicsAndRemovesExecutableContent(t *testing.T) {
	input := []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10" onclick="alert(1)"><defs><path id="shape" d="M0 0h10v10z"/></defs><style>.ok{background:url(http://test.com/a.jpg)}.bad{background:url(data:text/html,xx)}@import "https://evil.example/x.css";</style><use xlink:href="#shape"/><image xlink:href="https://test.com/logo.png" onload="alert(1)"/><image href="data:image/png;base64,AAA"/><image href="data:image/svg+xml;base64,AAA"/><a href="javascript:alert(1)">safe text</a><script>alert(1)</script><foreignObject><iframe src="https://evil.example"></iframe></foreignObject></svg>`)

	got, err := SanitizedLogoSVG(input)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{
		`<svg`,
		`<path`,
		`<use`,
		`href="#shape"`,
		`href="/logo.png"`,
		`href="data:image/png;base64,AAA"`,
		`safe text`,
		`background:url(/a.jpg)`,
		`background:url(#)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sanitized SVG missing %q: %s", want, body)
		}
	}
	for _, unwanted := range []string{`onclick=`, `onload=`, `<script`, `<foreignObject`, `<iframe`, `javascript:`, `data:image/svg+xml`, `@import`, `https://test.com`, `https://evil.example`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("sanitized SVG retained %q: %s", unwanted, body)
		}
	}
}

func TestSanitizedLogoSVGMatchesPinnedStandardImageDataURLPolicy(t *testing.T) {
	input := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><image id="jpeg" href="data:image/jpeg;base64,AAA"/><image id="png" href="data:image/png;base64,AAA"/><image id="gif" href="data:image/gif;base64,AAA"/><image id="svg" href="data:image/svg+xml;base64,AAA"/><image id="text" href="data:text/plain,meh"/><image id="bad" href="data://wat"/></svg>`)

	got, err := SanitizedLogoSVG(input)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, id := range []string{"jpeg", "png", "gif"} {
		if tag := svgTagWithID(body, id); !strings.Contains(tag, `href="data:image/`) {
			t.Fatalf("standard image data URL %q was not kept: %s", id, body)
		}
	}
	for _, id := range []string{"svg", "text", "bad"} {
		if tag := svgTagWithID(body, id); tag == "" || strings.Contains(tag, `href=`) {
			t.Fatalf("non-standard data URL %q was not dropped: %s", id, body)
		}
	}
}

func svgTagWithID(body, id string) string {
	start := strings.Index(body, `id="`+id+`"`)
	if start < 0 {
		return ""
	}
	start = strings.LastIndex(body[:start], "<")
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(body[start:], '>')
	if end < 0 {
		return ""
	}
	return body[start : start+end+1]
}

func TestSanitizedLogoSVGRejectsMalformedOrEmptyInput(t *testing.T) {
	for _, input := range [][]byte{
		[]byte(`<script>alert(1)</script>`),
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><path>`),
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg><svg xmlns="http://www.w3.org/2000/svg"></svg>`),
	} {
		if _, err := SanitizedLogoSVG(input); err == nil {
			t.Fatalf("invalid or empty SVG accepted: %q", input)
		}
	}
}

func TestSanitizedLogoSVGMatchesPinnedURLAndCSSFilters(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"http://test.com/a.jpg", "/a.jpg"},
		{"https://test.com:123/.././a/b/c.jpg", "/a/b/c.jpg"},
		{"/hello world.jpg", "/hello%20world.jpg"},
		{"b.jpg", "b.jpg"},
		{"./x/", "x/"},
		{"#hash", "#hash"},
		{"#", "#"},
		{"/image#", "/image#"},
		{"?q s", "?q%20s"},
		{"//host/PAth", "/PAth"},
		{"//host/%2fpath", "/%2fpath"},
	} {
		if got, ok := filterSVGURL(tc.input); !ok || got != tc.want {
			t.Errorf("filterSVGURL(%q)=(%q,%t), want %q,true", tc.input, got, ok, tc.want)
		}
	}
	for _, input := range []string{"//host%%%/path", "//host///path", "data:text/html,xx", "blob:123", "javascript:alert(1)", "jAvascript: alert(1)", "  jAvascript: alert(1) //http://"} {
		if got, ok := filterSVGURL(input); ok {
			t.Errorf("filterSVGURL(%q)=(%q,true), want dropped", input, got)
		}
	}
	for _, tc := range []struct{ input, want string }{
		{"hello, url(world)", "hello, url(world)"},
		{"hello, world", "hello, world"},
		{`url(/img?x="bad)`, "url(#)"},
		{"hello, url(http://evil.com)", "hello, url(#)"},
		{"hello, url( http://evil.com )", "hello, url(#)"},
		{"hello, url( //evil.com )", "hello, url(#)"},
		{"url( /okay ), (), bye", "url(/okay), (), bye"},
		{"hello, url( unclosed", "hello, url()"},
		{"hello, url( ) url(    ) bork", "hello, url() url() bork"},
		{"hello, url('1' )url(  2  ) bork", "hello, url(1)url(2) bork"},
		{"hello, url('(' )", "hello, url()"},
		{"aurl(burl(", "aurl()"},
		{"uurl()rl(", "uurl()rl("},
		{"ok:url(data:text/plain;base64,AAA)", "ok:url(#)"},
		{"color: red; background: URL(X); huh", "color: red; background: URL(X); huh"},
		{"@import 'foo'; FONT-size: 1em;", " FONT-size: 1em;"},
		{"u;url(data:x);rl(hack)", "u;url(#);rl(hack)"},
		{"font-size: 1em; @Import 'foo';", "font-size: 1em;"},
		{"color: red; background: URL(//x/rel);", "color: red; background: URL(/rel);"},
	} {
		if got := filteredSVGURLFunc(tc.input); got != tc.want {
			t.Errorf("filteredSVGURLFunc(%q)=%q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSanitizedLogoSVGEscapesFilteredStyleTextBeforeSerialization(t *testing.T) {
	input := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><style><![CDATA[</style><script>alert(1)</script><style>]]></style></svg>`)
	got, err := SanitizedLogoSVG(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `&lt;/style&gt;&lt;script&gt;`) {
		t.Fatalf("style text was not XML-escaped: %s", got)
	}

	decoder := xml.NewDecoder(strings.NewReader(string(got)))
	styleElements := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("sanitized output is not XML: %v; output=%s", err, got)
		}
		if start, ok := token.(xml.StartElement); ok {
			switch start.Name.Local {
			case "style":
				styleElements++
			case "script":
				t.Fatalf("sanitized style text reparsed as script: %s", got)
			}
		}
	}
	if styleElements != 1 {
		t.Fatalf("style element count=%d output=%s", styleElements, got)
	}
}
