// Minimal Cloudflare API v4 client (the few endpoints vps-relay needs).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const cfBase = "https://api.cloudflare.com/client/v4"

type cfEnvelope[T any] struct {
	Success bool      `json:"success"`
	Errors  []cfError `json:"errors"`
	Result  T         `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

var cfClient = &http.Client{Timeout: 10 * time.Second}

func cfDo(token, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, cfBase+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := cfClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var env cfEnvelope[json.RawMessage]
		if json.Unmarshal(raw, &env) == nil && len(env.Errors) > 0 {
			return nil, cfErrorList(env.Errors)
		}
		return nil, fmt.Errorf("Cloudflare HTTP %d", res.StatusCode)
	}
	return raw, nil
}

func cfVerifyToken(token string) error {
	if token == "" {
		return errors.New("empty token")
	}
	raw, err := cfDo(token, "GET", "/user/tokens/verify", nil)
	if err != nil {
		return err
	}
	var env cfEnvelope[struct {
		Status string `json:"status"`
	}]
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if !env.Success {
		return cfErrorList(env.Errors)
	}
	if env.Result.Status != "active" {
		return fmt.Errorf("token status: %s", env.Result.Status)
	}
	return nil
}

func cfListZones(token string) ([]cfZone, error) {
	raw, err := cfDo(token, "GET", "/zones?per_page=50", nil)
	if err != nil {
		return nil, err
	}
	var env cfEnvelope[[]cfZone]
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfErrorList(env.Errors)
	}
	return env.Result, nil
}

func cfFindZoneByName(token, name string) (*cfZone, error) {
	raw, err := cfDo(token, "GET", "/zones?name="+url.QueryEscape(name), nil)
	if err != nil {
		return nil, err
	}
	var env cfEnvelope[[]cfZone]
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfErrorList(env.Errors)
	}
	if len(env.Result) == 0 {
		return nil, fmt.Errorf("zone not found: %s", name)
	}
	return &env.Result[0], nil
}

// 完整读取同名记录，不能把查询失败或多记录误当成不存在。
func cfListRecords(token, zoneID, name string) ([]cfRecord, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("per_page", "100")
	var records []cfRecord
	for page := 1; ; page++ {
		q.Set("page", fmt.Sprint(page))
		raw, err := cfDo(token, "GET", "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var env cfEnvelope[[]cfRecord]
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, err
		}
		if !env.Success {
			return nil, cfErrorList(env.Errors)
		}
		records = append(records, env.Result...)
		if len(env.Result) < 100 {
			return records, nil
		}
	}
}

// PATCH 只修改接管所需字段，保留同一记录的 ID、备注和其他属性。
func cfUpdateRecord(token, zoneID, recordID string, rec cfRecord) (*cfRecord, error) {
	body := struct {
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}{rec.Content, rec.TTL, rec.Proxied}
	raw, err := cfDo(token, "PATCH", "/zones/"+zoneID+"/dns_records/"+recordID, body)
	if err != nil {
		return nil, err
	}
	var env cfEnvelope[cfRecord]
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfErrorList(env.Errors)
	}
	return &env.Result, nil
}

func cfCreateRecord(token, zoneID string, rec cfRecord) (*cfRecord, error) {
	raw, err := cfDo(token, "POST", "/zones/"+zoneID+"/dns_records", rec)
	if err != nil {
		return nil, err
	}
	var env cfEnvelope[cfRecord]
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, cfErrorList(env.Errors)
	}
	return &env.Result, nil
}

func cfDeleteRecord(token, zoneID, recordID string) error {
	raw, err := cfDo(token, "DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	if err != nil {
		return err
	}
	var env cfEnvelope[struct {
		ID string `json:"id"`
	}]
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	if !env.Success {
		return cfErrorList(env.Errors)
	}
	return nil
}

// Auto-detect the registrable zone name for a given hostname by checking
// progressively shorter suffixes against `cfListZones`.
func cfPickZoneFor(token, host string) (*cfZone, error) {
	zones, err := cfListZones(token)
	if err != nil {
		return nil, err
	}
	// Try the longest matching suffix.
	var match *cfZone
	for i := range zones {
		z := zones[i]
		if host == z.Name || endsWith(host, "."+z.Name) {
			if match == nil || len(z.Name) > len(match.Name) {
				match = &zones[i]
			}
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no Cloudflare zone in this account hosts %q", host)
	}
	return match, nil
}

func cfErrorList(errs []cfError) error {
	if len(errs) == 0 {
		return errors.New("cloudflare API failure (no detail)")
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
	}
	return errors.New("cloudflare API: " + joinComma(msgs))
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}
