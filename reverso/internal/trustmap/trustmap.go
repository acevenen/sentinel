// Package trustmap models roots of trust, certificates, keys, identities and
// authorization boundaries as a graph. It records where a key is referenced
// without ever holding private key material, and it can model the blast radius
// of a compromised node and the rotation it would require.
package trustmap

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// NodeKind classifies a trust-graph node.
type NodeKind string

// Node kinds.
const (
	KindRootOfTrust NodeKind = "root_of_trust"
	KindCertificate NodeKind = "certificate"
	KindPublicKey   NodeKind = "public_key"
	KindIdentity    NodeKind = "identity"
	KindService     NodeKind = "service"
	KindBoundary    NodeKind = "authorization_boundary"
)

// EdgeKind classifies a directed relationship between nodes.
type EdgeKind string

// Edge kinds.
const (
	EdgeSigns      EdgeKind = "signs"      // A signs B
	EdgeAuthorizes EdgeKind = "authorizes" // A authorizes B
	EdgeTrusts     EdgeKind = "trusts"     // A trusts B
	EdgeReferences EdgeKind = "references" // A references key/cert B
	EdgeVerifies   EdgeKind = "verifies"   // A verifies B
)

// KeyReference records that a key or certificate is used at a location, plus
// only public, non-sensitive metadata. There is deliberately no field for
// private key bytes: REVerso records the reference, never the secret.
type KeyReference struct {
	Label       string `json:"label"`
	Location    string `json:"location"`    // e.g. "partition2:/etc/keys/app.pub"
	EvidenceID  string `json:"evidence_id"` // artifact hash
	Algorithm   string `json:"algorithm,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // public fingerprint only
	IsPublic    bool   `json:"is_public"`             // true for public keys/certs
}

// Node is a vertex in the trust graph.
type Node struct {
	ID       string        `json:"id"`
	Kind     NodeKind      `json:"kind"`
	Label    string        `json:"label"`
	KeyRef   *KeyReference `json:"key_reference,omitempty"`
	Notes    []string      `json:"notes,omitempty"`
	Rotation string        `json:"rotation_requirement,omitempty"`
}

// Edge is a directed relationship.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}

// Graph is the whole trust map for a project.
type Graph struct {
	ProjectID string          `json:"project_id"`
	Nodes     map[string]Node `json:"nodes"`
	Edges     []Edge          `json:"edges"`
}

// Errors.
var (
	ErrDuplicateNode      = errors.New("node id already exists")
	ErrUnknownNode        = errors.New("edge references an unknown node")
	ErrPrivateKeyRejected = errors.New("trust map refuses to store private key material")
)

// New returns an empty graph for a project.
func New(projectID string) *Graph {
	return &Graph{ProjectID: projectID, Nodes: map[string]Node{}}
}

// AddNode inserts a node. A key reference that is not marked public is refused,
// enforcing "record where a key is referenced without extracting private
// material".
func (g *Graph) AddNode(n Node) error {
	if strings.TrimSpace(n.ID) == "" {
		return errors.New("node id is required")
	}
	if _, ok := g.Nodes[n.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateNode, n.ID)
	}
	if n.KeyRef != nil && !n.KeyRef.IsPublic {
		return fmt.Errorf("%w: %s", ErrPrivateKeyRejected, n.ID)
	}
	g.Nodes[n.ID] = n
	return nil
}

// AddEdge inserts an edge between two existing nodes.
func (g *Graph) AddEdge(e Edge) error {
	if _, ok := g.Nodes[e.From]; !ok {
		return fmt.Errorf("%w: from %s", ErrUnknownNode, e.From)
	}
	if _, ok := g.Nodes[e.To]; !ok {
		return fmt.Errorf("%w: to %s", ErrUnknownNode, e.To)
	}
	g.Edges = append(g.Edges, e)
	return nil
}

// Roots returns nodes that are roots of trust or have no incoming trust edges.
func (g *Graph) Roots() []string {
	hasIncoming := map[string]bool{}
	for _, e := range g.Edges {
		hasIncoming[e.To] = true
	}
	var roots []string
	for id, n := range g.Nodes {
		if n.Kind == KindRootOfTrust || !hasIncoming[id] {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	return roots
}

// CompromiseImpact returns the set of nodes reachable from a compromised node,
// i.e. everything that trusts or is authorized/signed/verified by it, directly
// or transitively. This models the blast radius of a key compromise.
func (g *Graph) CompromiseImpact(nodeID string) ([]string, error) {
	if _, ok := g.Nodes[nodeID]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownNode, nodeID)
	}
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	seen := map[string]bool{}
	var stack []string
	stack = append(stack, adj[nodeID]...)
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] || cur == nodeID {
			continue
		}
		seen[cur] = true
		stack = append(stack, adj[cur]...)
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// DOT renders the graph in Graphviz DOT for visualization.
func (g *Graph) DOT() string {
	var b strings.Builder
	b.WriteString("digraph trustmap {\n  rankdir=LR;\n")
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := g.Nodes[id]
		label := n.Label
		if label == "" {
			label = id
		}
		fmt.Fprintf(&b, "  %q [label=%q, shape=box, xlabel=%q];\n", id, label, n.Kind)
	}
	for _, e := range g.Edges {
		fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", e.From, e.To, e.Kind)
	}
	b.WriteString("}\n")
	return b.String()
}
