// Package fixture defines the test-only Unix-socket backend protocol. Neither
// the harness nor this protocol is installed in the production package.
package fixture

const APISecret = "synthetic-integration-api-secret"

// Event logs metadata only: never headers, passwords, tokens, or response bodies.
type Event struct {
	Kind      string `json:"kind"`
	Operation string `json:"operation,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
}

type Reply struct {
	Status         int    `json:"status"`
	Body           string `json:"body"`
	TransportError bool   `json:"transport_error"`
}
