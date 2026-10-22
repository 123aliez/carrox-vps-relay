package main

import (
	"fmt"
	"net"
	"strings"
)

// DNSChange 随站点元数据持久保存，区分新建、接管和复用已有记录。
type DNSChange struct {
	Mode    string    `json:"mode"`
	ZoneID  string    `json:"zone_id"`
	Before  *cfRecord `json:"before,omitempty"`
	After   cfRecord  `json:"after"`
	Pending bool      `json:"pending,omitempty"`
}

func sameRecord(a, b cfRecord) bool {
	return a.ID == b.ID && a.Type == b.Type && strings.EqualFold(a.Name, b.Name) &&
		a.Content == b.Content && a.TTL == b.TTL && a.Proxied == b.Proxied
}

func planDNS(token string, zone cfZone, domain, edge string) (*DNSChange, error) {
	if ip := net.ParseIP(edge); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("无效的中转 IPv4: %s", edge)
	}
	records, err := cfListRecords(token, zone.ID, domain)
	if err != nil {
		return nil, fmt.Errorf("查询 DNS 失败: %w", err)
	}
	change := &DNSChange{Mode: "created", ZoneID: zone.ID, Pending: true,
		After: cfRecord{Type: "A", Name: domain, Content: edge, TTL: 60}}
	for _, rec := range records {
		switch rec.Type {
		case "AAAA", "CNAME":
			return nil, fmt.Errorf("%s 存在 %s 记录，请先处理同名解析后创建中转", domain, rec.Type)
		case "A":
			if change.Before != nil {
				return nil, fmt.Errorf("%s 存在多条 A 记录，请先明确保留的源站记录", domain)
			}
			original := rec
			change.Before = &original
			change.After = rec
			change.After.Content = edge
			change.After.Proxied = false
			change.Mode = "replaced"
			if sameRecord(rec, change.After) {
				change.Mode = "reused"
			}
		}
	}
	return change, nil
}

func validateRelayUpstream(domain, upstream, edge string) error {
	_, host, _, _, err := parseUpstream(upstream)
	if err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), domain) {
		return fmt.Errorf("上游不能使用加速域名自身，请填写原服务器 IP 或独立源站域名")
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsUnspecified() || ip.Equal(net.ParseIP(edge))) {
		return fmt.Errorf("上游不能指向中转机自身")
	}
	return nil
}

func (d *DNSChange) apply(token string) error {
	// 证书准备期间可能有人改过 DNS，切换前再次确认。
	records, err := cfListRecords(token, d.ZoneID, d.After.Name)
	if err != nil {
		return err
	}
	var addresses []cfRecord
	for _, rec := range records {
		if rec.Type == "A" || rec.Type == "AAAA" || rec.Type == "CNAME" {
			addresses = append(addresses, rec)
		}
	}
	if d.Before != nil {
		if len(addresses) != 1 || !sameRecord(addresses[0], *d.Before) {
			return fmt.Errorf("DNS 已被外部修改，已取消切换")
		}
	} else if len(addresses) != 0 {
		return fmt.Errorf("DNS 已新增同名解析，已取消切换")
	}
	var record *cfRecord
	switch d.Mode {
	case "created":
		record, err = cfCreateRecord(token, d.ZoneID, d.After)
	case "replaced":
		record, err = cfUpdateRecord(token, d.ZoneID, d.Before.ID, d.After)
	case "reused":
		d.Pending = false
		return nil
	default:
		return fmt.Errorf("未知的 DNS 操作: %s", d.Mode)
	}
	if err != nil {
		// 超时不代表服务端未写入，保留原快照供后续核对和恢复。
		return fmt.Errorf("切换 DNS 失败: %w", err)
	}
	d.After = *record
	d.Pending = false
	return nil
}

// release 允许重复执行；外部修改冲突时保留配置，让用户处理后重试。
func (d *DNSChange) release(token string) error {
	if d.Mode == "reused" {
		return nil
	}
	if d.Mode != "created" && d.Mode != "replaced" {
		return fmt.Errorf("未知的 DNS 来源，保留现有解析")
	}
	if d.Mode == "replaced" && d.Before == nil {
		return fmt.Errorf("缺少原 DNS 快照，保留当前记录及站点配置")
	}
	records, err := cfListRecords(token, d.ZoneID, d.After.Name)
	if err != nil {
		return err
	}
	var current *cfRecord
	for i := range records {
		if records[i].ID == d.After.ID && d.After.ID != "" {
			current = &records[i]
			break
		}
	}
	if d.After.ID == "" {
		// 新建请求可能在响应丢失前完成；没有可靠 ID 时禁止猜测并删除。
		for _, rec := range records {
			if rec.Type == "A" {
				return fmt.Errorf("新建 DNS 的结果不确定，请核对 Cloudflare 记录；站点恢复信息已保留")
			}
		}
		return nil
	}
	if current == nil {
		if d.Mode == "created" {
			return nil
		}
		return fmt.Errorf("原 DNS 记录已不存在，无法按原 ID 恢复")
	}
	if d.Before != nil && sameRecord(*current, *d.Before) {
		return nil
	}
	if !sameRecord(*current, d.After) {
		return fmt.Errorf("DNS 已被外部修改，保留当前记录及站点配置")
	}
	if d.Mode == "created" {
		return cfDeleteRecord(token, d.ZoneID, current.ID)
	}
	_, err = cfUpdateRecord(token, d.ZoneID, current.ID, *d.Before)
	return err
}
