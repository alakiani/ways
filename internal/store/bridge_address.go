package store

import "context"

// AddressMember is a Bridge the Bridge Address's record holds (ADR 0011).
type AddressMember struct {
	NodeID string
	Joined int64 // Unix time it joined
}

// BridgeAddress returns the Bridges the Bridge Address holds, by Node id.
func (s *Store) BridgeAddress(ctx context.Context) ([]AddressMember, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, joined_at FROM bridge_address ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AddressMember
	for rows.Next() {
		var m AddressMember
		if err := rows.Scan(&m.NodeID, &m.Joined); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// JoinBridgeAddress adds a Bridge to the Bridge Address; one already in it
// keeps its join time.
func (s *Store) JoinBridgeAddress(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO bridge_address (node_id, joined_at) VALUES (?, ?)
		ON CONFLICT (node_id) DO NOTHING`, nodeID, s.unix())
	return err
}

// LeaveBridgeAddress takes a Bridge out of the Bridge Address.
func (s *Store) LeaveBridgeAddress(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM bridge_address WHERE node_id = ?`, nodeID)
	return err
}
