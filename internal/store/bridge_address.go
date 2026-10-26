package store

import "context"

// Record names one of the two Bridge Addresses' records: the Bridge
// Address's (ADR 0011) or the Abroad Bridge Address's (ADR 0014).
type Record string

const (
	BridgeRecord Record = "bridge_address"
	AbroadRecord Record = "abroad_address"
)

// AddressMember is a Bridge a Bridge Address's record holds.
type AddressMember struct {
	NodeID string
	Joined int64 // Unix time it joined
}

// AddressMembers returns the Bridges a record holds, by Node id.
func (s *Store) AddressMembers(ctx context.Context, rec Record) ([]AddressMember, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, joined_at FROM `+string(rec)+` ORDER BY node_id`)
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

// JoinAddress adds a Bridge to a record; one already in it keeps its join
// time.
func (s *Store) JoinAddress(ctx context.Context, rec Record, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO `+string(rec)+` (node_id, joined_at) VALUES (?, ?)
		ON CONFLICT (node_id) DO NOTHING`, nodeID, s.unix())
	return err
}

// LeaveAddress takes a Bridge out of a record.
func (s *Store) LeaveAddress(ctx context.Context, rec Record, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM `+string(rec)+` WHERE node_id = ?`, nodeID)
	return err
}
