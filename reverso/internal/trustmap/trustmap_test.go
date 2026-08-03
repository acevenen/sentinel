package trustmap

import (
	"errors"
	"reflect"
	"testing"
)

func TestRefusesPrivateKeyMaterial(t *testing.T) {
	g := New("p")
	err := g.AddNode(Node{
		ID: "k1", Kind: KindPublicKey,
		KeyRef: &KeyReference{Label: "app key", Location: "/keys/app.key", IsPublic: false},
	})
	if !errors.Is(err, ErrPrivateKeyRejected) {
		t.Fatalf("AddNode error = %v, want ErrPrivateKeyRejected", err)
	}
}

func TestAcceptsPublicKeyReference(t *testing.T) {
	g := New("p")
	err := g.AddNode(Node{
		ID: "k1", Kind: KindPublicKey,
		KeyRef: &KeyReference{Label: "app pub", Location: "/keys/app.pub", IsPublic: true, Fingerprint: "SHA256:abc"},
	})
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
}

func TestEdgeRequiresKnownNodes(t *testing.T) {
	g := New("p")
	_ = g.AddNode(Node{ID: "a", Kind: KindRootOfTrust})
	if err := g.AddEdge(Edge{From: "a", To: "missing", Kind: EdgeSigns}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("AddEdge error = %v, want ErrUnknownNode", err)
	}
}

func TestCompromiseImpact(t *testing.T) {
	g := New("p")
	for _, id := range []string{"root", "ca", "svc", "leaf"} {
		if err := g.AddNode(Node{ID: id, Kind: KindService}); err != nil {
			t.Fatalf("AddNode %s: %v", id, err)
		}
	}
	_ = g.AddEdge(Edge{From: "root", To: "ca", Kind: EdgeSigns})
	_ = g.AddEdge(Edge{From: "ca", To: "svc", Kind: EdgeSigns})
	_ = g.AddEdge(Edge{From: "svc", To: "leaf", Kind: EdgeAuthorizes})

	impact, err := g.CompromiseImpact("root")
	if err != nil {
		t.Fatalf("CompromiseImpact: %v", err)
	}
	want := []string{"ca", "leaf", "svc"}
	if !reflect.DeepEqual(impact, want) {
		t.Fatalf("impact = %v, want %v", impact, want)
	}
}

func TestRootsDetection(t *testing.T) {
	g := New("p")
	_ = g.AddNode(Node{ID: "root", Kind: KindRootOfTrust})
	_ = g.AddNode(Node{ID: "child", Kind: KindService})
	_ = g.AddEdge(Edge{From: "root", To: "child", Kind: EdgeSigns})
	roots := g.Roots()
	if len(roots) != 1 || roots[0] != "root" {
		t.Fatalf("Roots = %v, want [root]", roots)
	}
}

func TestDOTRenders(t *testing.T) {
	g := New("p")
	_ = g.AddNode(Node{ID: "root", Kind: KindRootOfTrust, Label: "Boot ROM"})
	_ = g.AddNode(Node{ID: "svc", Kind: KindService})
	_ = g.AddEdge(Edge{From: "root", To: "svc", Kind: EdgeVerifies})
	dot := g.DOT()
	if !contains(dot, "digraph trustmap") || !contains(dot, "root") {
		t.Fatalf("DOT output looks wrong:\n%s", dot)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
