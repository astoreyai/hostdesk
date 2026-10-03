package discovery

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/astoreyai/hostdesk/internal/model"
)

func iptablesBypass(data []byte) bool {
	accept := false
	tailscaleJump, ufwJump, inputIndex := -1, -1, 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "-A ts-input ") && strings.Contains(line, " -j ACCEPT") {
			accept = true
		}
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		if strings.Contains(line, " -j ts-input") && tailscaleJump < 0 {
			tailscaleJump = inputIndex
		}
		if strings.Contains(line, " -j ufw-") && ufwJump < 0 {
			ufwJump = inputIndex
		}
		inputIndex++
	}
	return accept && tailscaleJump >= 0 && ufwJump >= 0 && tailscaleJump < ufwJump
}

type nftRule struct {
	Family string                       `json:"family"`
	Table  string                       `json:"table"`
	Chain  string                       `json:"chain"`
	Expr   []map[string]json.RawMessage `json:"expr"`
}

func nftBypass(data []byte) (bool, error) {
	var document struct {
		Nftables []struct {
			Rule *nftRule `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return false, err
	}
	type chainOrder struct {
		count int
		tail  int
		ufw   int
	}
	chains := map[string]*chainOrder{}
	accepted := map[string]bool{}
	for _, entry := range document.Nftables {
		if entry.Rule == nil {
			continue
		}
		rule := entry.Rule
		key := rule.Family + "/" + rule.Table
		chainKey := key + "/" + rule.Chain
		order := chains[chainKey]
		if order == nil {
			order = &chainOrder{tail: -1, ufw: -1}
			chains[chainKey] = order
		}
		for _, expr := range rule.Expr {
			if _, ok := expr["accept"]; ok && rule.Chain == "ts-input" {
				accepted[key] = true
			}
			for _, verdict := range []string{"jump", "goto"} {
				raw, ok := expr[verdict]
				if !ok {
					continue
				}
				var jump struct {
					Target string `json:"target"`
				}
				if json.Unmarshal(raw, &jump) != nil {
					continue
				}
				if jump.Target == "ts-input" && order.tail < 0 {
					order.tail = order.count
				}
				if strings.HasPrefix(jump.Target, "ufw-") && order.ufw < 0 {
					order.ufw = order.count
				}
			}
		}
		order.count++
	}
	for key, order := range chains {
		last := strings.LastIndexByte(key, '/')
		if last >= 0 && accepted[key[:last]] && order.tail >= 0 && order.ufw >= 0 && order.tail < order.ufw {
			return true, nil
		}
	}
	return false, nil
}

func collectFirewall(ctx context.Context) ([]model.Source, []string) {
	sources := []model.Source{}
	warnings := []string{}
	bypass, observed := false, false
	for _, name := range []string{"iptables-save", "ip6tables-save"} {
		data, err := run(ctx, name, "-t", "filter")
		s := source("firewall:"+name, err)
		if err == nil {
			observed = true
			bypass = bypass || iptablesBypass(data)
		}
		sources = append(sources, s)
	}
	data, err := run(ctx, "nft", "--json", "list", "ruleset")
	nftSource := source("firewall:nft", err)
	if err == nil {
		observed = true
		found, decodeErr := nftBypass(data)
		if decodeErr != nil {
			partial(&nftSource, "nftables evidence could not be decoded")
		} else {
			bypass = bypass || found
		}
	}
	sources = append(sources, nftSource)
	data, err = run(ctx, "ufw", "status", "verbose")
	ufwSource := source("firewall:ufw", err)
	if err == nil {
		if strings.Contains(string(data), "Status: active") {
			warnings = append(warnings, "UFW reports active configuration. This alone does not establish effective filtering; earlier accepts, other hook priorities and forwarded container traffic must be considered.")
		} else if strings.Contains(string(data), "Status: inactive") {
			warnings = append(warnings, "UFW reports inactive; nftables, other firewall managers or upstream controls may still filter traffic.")
		} else {
			partial(&ufwSource, "UFW status was not recognized")
		}
	}
	sources = append(sources, ufwSource)
	if bypass {
		warnings = append(warnings, "Firewall evidence: ts-input contains ACCEPT rules and is reached before UFW chains. Matching Tailscale traffic can bypass later UFW denies. A separate earlier-priority hook can still block that traffic; do not treat UFW denies alone as effective protection.")
	}
	if !observed {
		warnings = append(warnings, "Effective kernel firewall rules could not be inspected. Exposure labels describe socket bindings only, not firewall policy or internet reachability.")
	}
	if ctx.Err() != nil {
		warnings = append(warnings, "Firewall evidence is incomplete: collection deadline or cancellation.")
	}
	return sources, warnings
}
