package storage

import (
	"context"
	"slices"
	"time"

	"perimeter/ent"
	"perimeter/ent/ip"
	"perimeter/ent/target"
)

// RescanKinds picks which scans a rescan queues. SSL is left out when SSL
// Labs scanning is off: its producer never runs, so the flag would stay set.
type RescanKinds struct {
	SSL   bool
	CSP   bool
	Ports bool
}

// RescanCooldown is a target that was rescanned too recently, and when it may
// be rescanned again.
type RescanCooldown struct {
	ID      int
	RetryAt time.Time
}

// RescanResult says what happened to each requested id. Ids that are unknown
// or soft-deleted are NotFound.
type RescanResult struct {
	Queued      []int
	CoolingDown []RescanCooldown
	NotFound    []int
}

// RequestRescan asks for an on-demand scan of the live targets among ids. It
// sets rescan_requested_at and the pending flags that the producers read, so
// the flagged rows are scanned next. A target whose last request is less than
// cooldown old is left alone and reported as CoolingDown. All of it runs in
// one transaction.
func (s *EntStorage) RequestRescan(ctx context.Context, ids []int, now time.Time, cooldown time.Duration, kinds RescanKinds) (RescanResult, error) {
	var res RescanResult

	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) == 0 {
		return res, nil
	}

	tx, err := s.client.Tx(ctx)
	if err != nil {
		return res, err
	}

	// The soft-delete filter applies, so deleted targets are not found here.
	live := make(map[int]*ent.Target, len(sorted))
	for chunk := range slices.Chunk(sorted, bulkChunkSize) {
		found, err := tx.Target.Query().Where(target.IDIn(chunk...)).All(ctx)
		if err != nil {
			return res, rollback(tx, err)
		}
		for _, t := range found {
			live[t.ID] = t
		}
	}

	var queued []int
	for _, id := range sorted {
		t, ok := live[id]
		if !ok {
			res.NotFound = append(res.NotFound, id)
			continue
		}
		if t.RescanRequestedAt != nil && now.Sub(*t.RescanRequestedAt) < cooldown {
			res.CoolingDown = append(res.CoolingDown, RescanCooldown{ID: id, RetryAt: t.RescanRequestedAt.Add(cooldown)})
			continue
		}
		queued = append(queued, id)
	}
	res.Queued = queued

	// IPs are flagged by the target, so a target with no IPs yet has nothing
	// to flag for ports: resolution is pending anyway.
	for chunk := range slices.Chunk(queued, bulkChunkSize) {
		if err := requestRescanChunk(ctx, tx, chunk, now, kinds); err != nil {
			return res, rollback(tx, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return RescanResult{}, err
	}
	return res, nil
}

// requestRescanChunk stamps and flags one chunk of queued targets.
func requestRescanChunk(ctx context.Context, tx *ent.Tx, ids []int, now time.Time, kinds RescanKinds) error {
	// A rescan resolves the name again first, so new addresses in the answer
	// are picked up and port-scanned as never scanned (issue #59).
	if _, err := tx.Target.Update().
		Where(target.IDIn(ids...)).
		SetRescanRequestedAt(now).
		ClearNextResolveAt().
		Save(ctx); err != nil {
		return err
	}

	// SSL and CSP are for domains only; an IP target is scanned for ports.
	if kinds.SSL || kinds.CSP {
		u := tx.Target.Update().Where(target.IDIn(ids...), target.IsIP(false))
		if kinds.SSL {
			u.SetSslRescanPending(true)
		}
		if kinds.CSP {
			u.SetCspRescanPending(true)
		}
		if _, err := u.Save(ctx); err != nil {
			return err
		}
	}

	if kinds.Ports {
		if _, err := tx.IP.Update().
			Where(ip.HasTargetsWith(target.IDIn(ids...))).
			SetRescanPending(true).
			Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// clearTargetRescan clears a target's pending SSL or CSP rescan once a result
// is stored. It only writes when the flag is set, so an ordinary scan does not
// touch the row.
func clearTargetRescan(ctx context.Context, tx *ent.Tx, id int, scanType ScanType) error {
	u := tx.Target.Update().Where(target.IDEQ(id))
	switch scanType {
	case ScanTypeSSL:
		u.Where(target.SslRescanPending(true)).SetSslRescanPending(false)
	case ScanTypeCSP:
		u.Where(target.CspRescanPending(true)).SetCspRescanPending(false)
	}
	_, err := u.Save(ctx)
	return err
}

// clearIPRescan clears an IP's pending port rescan once a port scan result is
// stored.
func (s *EntStorage) clearIPRescan(ctx context.Context, i *ent.IP) error {
	_, err := s.client.IP.Update().
		Where(ip.IDEQ(i.ID), ip.RescanPending(true)).
		SetRescanPending(false).
		Save(ctx)
	return err
}
