package pathutil

import "testing"

func TestNormalizePrefix(t *testing.T) {
	valid := map[string]string{
		"/higobase-admin":  "/higobase-admin",
		"/higobase-admin/": "/higobase-admin",
		"  /a/b  ":         "/a/b",
		"/api/v1":          "/api/v1",
		"/V1":              "/V1",
		"/a-b_c.d":         "/a-b_c.d",
	}
	for in, want := range valid {
		got, err := NormalizePrefix(in)
		if err != nil {
			t.Errorf("NormalizePrefix(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizePrefix(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"", "  ", "api", "/", "//", "/a//b", "/a/../b", "/a/./b",
		"/_cproxy", "/_cproxy/x", "/a b", "/a?b", "/a#b", "/a%20b", "/a\\b", "/%2e",
	}
	for _, in := range invalid {
		if got, err := NormalizePrefix(in); err == nil {
			t.Errorf("NormalizePrefix(%q) = %q, want an error", in, got)
		}
	}
}

func TestMatchPrefix(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/higobase-admin", "/higobase-admin", true},
		{"/higobase-admin/", "/higobase-admin", true},
		{"/higobase-admin/x/y", "/higobase-admin", true},
		{"/higobase-adminx", "/higobase-admin", false},
		{"/higobase", "/higobase-admin", false},
		{"/", "/higobase-admin", false},
	}
	for _, c := range cases {
		if got := MatchPrefix(c.path, c.prefix); got != c.want {
			t.Errorf("MatchPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
	}
}

func TestStripPrefix(t *testing.T) {
	cases := []struct{ path, prefix, want string }{
		{"/api", "/api", "/"},
		{"/api/", "/api", "/"},
		{"/api/users", "/api", "/users"},
		{"/api/a/b", "/api", "/a/b"},
	}
	for _, c := range cases {
		if got := StripPrefix(c.path, c.prefix); got != c.want {
			t.Errorf("StripPrefix(%q, %q) = %q, want %q", c.path, c.prefix, got, c.want)
		}
	}
}

func TestOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a/b", "/a", true},
		{"/a", "/ab", false},
		{"/a/b", "/a/c", false},
	}
	for _, c := range cases {
		if got := Overlap(c.a, c.b); got != c.want {
			t.Errorf("Overlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestValidRequestPath(t *testing.T) {
	valid := []string{"/", "/a", "/higobase-admin/index.html", "/a/b?c", "/a%20b"}
	for _, p := range valid {
		if !ValidRequestPath(p) {
			t.Errorf("ValidRequestPath(%q) = false, want true", p)
		}
	}
	invalid := []string{"", "a", "//a", "/a//b", "/a/../b", "/a\\b", "/a\x00b"}
	for _, p := range invalid {
		if ValidRequestPath(p) {
			t.Errorf("ValidRequestPath(%q) = true, want false", p)
		}
	}
}

func TestIsReserved(t *testing.T) {
	if !IsReserved("/_cproxy") || !IsReserved("/_cproxy/tunnel") || !IsReserved("/_cproxy/x") {
		t.Error("reserved paths were not detected")
	}
	if IsReserved("/_cproxyx") || IsReserved("/higobase-admin") {
		t.Error("non-reserved paths were reported as reserved")
	}
}
