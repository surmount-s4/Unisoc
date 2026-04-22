package correlationengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type procEdgeRow struct {
	Host              string
	EventID           string
	ProcessGuid       string
	ParentProcessGuid string
	ProcessID         string
	ParentProcessID   string
	SourceProcessGuid string
	SourceProcessID   string
	TargetProcessGuid string
	TargetProcessID   string
	TimeCreated       time.Time
}

type creationNode struct {
	LastSeen  time.Time `json:"last_seen"`
	ProcessID string    `json:"process_id"`
	Children  []string  `json:"children"`
	Parents   []string  `json:"parents"`
}

type sourceTargetNode struct {
	LastSeen  time.Time `json:"last_seen"`
	ProcessID string    `json:"process_id"`
	Outgoing  []string  `json:"outgoing"`
	Incoming  []string  `json:"incoming"`
}

func (e *Engine) buildAndStoreProcessChains(ctx context.Context, start, end time.Time, hosts []string) (map[string]map[string]any, error) {
	evidence := make(map[string]map[string]any)
	hosts = uniqueNonEmpty(hosts)
	if len(hosts) == 0 {
		return evidence, nil
	}

	rows, err := e.db.Pool().Query(ctx, `
		SELECT
			COALESCE(NULLIF(agent_host,''), NULLIF(computer_0,''), 'unknown') AS host,
			COALESCE(eventid_0,''),
			COALESCE(processguid_2,''), COALESCE(parentprocessguid_2,''),
			COALESCE(processid_2,''), COALESCE(parentprocessid_2,''),
			COALESCE(sourceprocessguid_2,''), COALESCE(sourceprocessid_2,''),
			COALESCE(targetprocessguid_2,''), COALESCE(targetprocessid_2,''),
			COALESCE(timestamp, NOW())
		FROM security_events
		WHERE timestamp >= $1
		  AND timestamp < $2
		  AND COALESCE(NULLIF(agent_host,''), NULLIF(computer_0,''), 'unknown') = ANY($3)
		  AND COALESCE(providername_0,'') = 'Microsoft-Windows-Sysmon'
		ORDER BY timestamp ASC
	`, start, end, hosts)
	if err != nil {
		return nil, fmt.Errorf("query process chain rows: %w", err)
	}
	defer rows.Close()

	byHostCreation := make(map[string]map[string]*creationNode)
	byHostSourceTarget := make(map[string]map[string]*sourceTargetNode)

	for rows.Next() {
		var r procEdgeRow
		if err := rows.Scan(
			&r.Host, &r.EventID,
			&r.ProcessGuid, &r.ParentProcessGuid,
			&r.ProcessID, &r.ParentProcessID,
			&r.SourceProcessGuid, &r.SourceProcessID,
			&r.TargetProcessGuid, &r.TargetProcessID,
			&r.TimeCreated,
		); err != nil {
			continue
		}

		host := strings.TrimSpace(r.Host)
		if host == "" {
			host = "unknown"
		}
		if _, ok := byHostCreation[host]; !ok {
			byHostCreation[host] = make(map[string]*creationNode)
		}
		if _, ok := byHostSourceTarget[host]; !ok {
			byHostSourceTarget[host] = make(map[string]*sourceTargetNode)
		}

		e.processCreationEvent(byHostCreation[host], r)
		e.processSourceTargetEvent(byHostSourceTarget[host], r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, host := range hosts {
		h := host
		if strings.TrimSpace(h) == "" {
			h = "unknown"
		}

		creationTree := byHostCreation[h]
		if creationTree == nil {
			creationTree = make(map[string]*creationNode)
		}

		sourceTargetTree := byHostSourceTarget[h]
		if sourceTargetTree == nil {
			sourceTargetTree = make(map[string]*sourceTargetNode)
		}

		if err := e.upsertProcessChain(ctx, start, end, h, "creation_tree", creationTree); err != nil {
			return nil, err
		}
		if err := e.upsertProcessChain(ctx, start, end, h, "source_target_tree", sourceTargetTree); err != nil {
			return nil, err
		}

		evidence[h] = map[string]any{
			"creation_tree":      creationTree,
			"source_target_tree": sourceTargetTree,
			"stats": map[string]any{
				"creation_nodes":      countChainNodes(creationTree),
				"source_target_nodes": countChainNodes(sourceTargetTree),
			},
		}
	}

	return evidence, nil
}

func (e *Engine) processCreationEvent(tree map[string]*creationNode, r procEdgeRow) {
	pg := strings.TrimSpace(r.ProcessGuid)
	parent := strings.TrimSpace(r.ParentProcessGuid)
	isCreate := strings.TrimSpace(r.EventID) == "1"

	if pg != "" {
		node, ok := tree[pg]
		if !ok {
			node = &creationNode{LastSeen: r.TimeCreated, ProcessID: r.ProcessID}
			tree[pg] = node
		}
		if r.TimeCreated.After(node.LastSeen) {
			node.LastSeen = r.TimeCreated
		}
		if isCreate && parent != "" {
			node.Parents = appendUnique(node.Parents, parent)
		}
	}

	if isCreate && parent != "" {
		pnode, ok := tree[parent]
		if !ok {
			pnode = &creationNode{LastSeen: r.TimeCreated, ProcessID: r.ParentProcessID}
			tree[parent] = pnode
		}
		if r.TimeCreated.After(pnode.LastSeen) {
			pnode.LastSeen = r.TimeCreated
		}
		if pg != "" {
			pnode.Children = appendUnique(pnode.Children, pg)
		}
	}
}

func (e *Engine) processSourceTargetEvent(tree map[string]*sourceTargetNode, r procEdgeRow) {
	eventID := strings.TrimSpace(r.EventID)
	if eventID != "8" && eventID != "10" {
		return
	}
	from := strings.TrimSpace(r.SourceProcessGuid)
	to := strings.TrimSpace(r.TargetProcessGuid)

	if from != "" {
		n, ok := tree[from]
		if !ok {
			n = &sourceTargetNode{LastSeen: r.TimeCreated, ProcessID: r.SourceProcessID}
			tree[from] = n
		}
		if r.TimeCreated.After(n.LastSeen) {
			n.LastSeen = r.TimeCreated
		}
		if to != "" {
			n.Outgoing = appendUnique(n.Outgoing, to)
		}
	}

	if to != "" {
		n, ok := tree[to]
		if !ok {
			n = &sourceTargetNode{LastSeen: r.TimeCreated, ProcessID: r.TargetProcessID}
			tree[to] = n
		}
		if r.TimeCreated.After(n.LastSeen) {
			n.LastSeen = r.TimeCreated
		}
		if from != "" {
			n.Incoming = appendUnique(n.Incoming, from)
		}
	}
}

func (e *Engine) upsertProcessChain(ctx context.Context, start, end time.Time, host, chainType string, chain any) error {
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return fmt.Errorf("marshal %s chain: %w", chainType, err)
	}

	stats := map[string]any{"nodes": countChainNodes(chain)}
	statsJSON, _ := json.Marshal(stats)

	_, err = e.db.Pool().Exec(ctx, `
		INSERT INTO process_chain (window_start, window_end, source_host, chain_type, chain_json, stats_json)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (window_start, window_end, source_host, chain_type)
		DO UPDATE SET chain_json = EXCLUDED.chain_json,
		              stats_json = EXCLUDED.stats_json,
		              created_at = NOW()
	`, start, end, host, chainType, chainJSON, statsJSON)
	if err != nil {
		return fmt.Errorf("upsert process_chain %s/%s: %w", host, chainType, err)
	}
	return nil
}

func appendUnique(items []string, v string) []string {
	if v == "" {
		return items
	}
	for _, it := range items {
		if it == v {
			return items
		}
	}
	return append(items, v)
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func countChainNodes(chain any) int {
	switch t := chain.(type) {
	case map[string]*creationNode:
		return len(t)
	case map[string]*sourceTargetNode:
		return len(t)
	default:
		return 0
	}
}
