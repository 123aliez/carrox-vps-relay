package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeCF struct {
	mu                 sync.Mutex
	records            map[string]cfRecord
	writes             []string
	failList           bool
	failPatch          bool
	losePatchResponse  bool
	loseCreateResponse bool
}

var originRecord = cfRecord{ID: "original-id", Type: "A", Name: "redvpn.example.com", Content: "23.95.8.179", TTL: 1}
var testZone = cfZone{ID: "zone-id", Name: "example.com"}

func newFakeCF(t *testing.T, records ...cfRecord) *fakeCF {
	t.Helper()
	f := &fakeCF{records: map[string]cfRecord{}}
	for _, rec := range records {
		f.records[rec.ID] = rec
	}
	server := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	base, _ := url.Parse(server.URL)
	old := cfClient
	cfClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Scheme, copy.URL.Host = base.Scheme, base.Host
		return http.DefaultTransport.RoundTrip(copy)
	})}
	t.Cleanup(func() { cfClient = old; server.Close() })
	return f
}

func (f *fakeCF) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	prefix := "/client/v4/zones/zone-id/dns_records"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
	result := func(value any) { _ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": value}) }
	fail := func() {
		w.WriteHeader(502)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":999,"message":"模拟接口失败"}]}`))
	}
	switch r.Method {
	case "GET":
		if f.failList {
			fail()
			return
		}
		if id != "" {
			result(f.records[id])
			return
		}
		list := []cfRecord{}
		for _, record := range f.records {
			if record.Name == r.URL.Query().Get("name") {
				list = append(list, record)
			}
		}
		result(list)
	case "PATCH":
		if f.failPatch {
			fail()
			return
		}
		rec, ok := f.records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		var patch map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&patch) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if len(patch) != 3 || patch["content"] == nil || patch["ttl"] == nil || patch["proxied"] == nil {
			http.Error(w, "只能更新 content/ttl/proxied", 400)
			return
		}
		_ = json.Unmarshal(patch["content"], &rec.Content)
		_ = json.Unmarshal(patch["ttl"], &rec.TTL)
		_ = json.Unmarshal(patch["proxied"], &rec.Proxied)
		f.records[id] = rec
		f.writes = append(f.writes, "PATCH:"+id)
		if f.losePatchResponse {
			f.losePatchResponse = false
			fail()
			return
		}
		result(rec)
	case "POST":
		var rec cfRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = "new-id"
		f.records[rec.ID] = rec
		f.writes = append(f.writes, "POST:"+rec.ID)
		if f.loseCreateResponse {
			f.loseCreateResponse = false
			fail()
			return
		}
		result(rec)
	case "DELETE":
		delete(f.records, id)
		f.writes = append(f.writes, "DELETE:"+id)
		result(map[string]string{"id": id})
	default:
		http.Error(w, "unsupported", 405)
	}
}

func (f *fakeCF) snapshot() (map[string]cfRecord, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	records := map[string]cfRecord{}
	for id, rec := range f.records {
		records[id] = rec
	}
	return records, append([]string(nil), f.writes...)
}

func TestTakeoverUpdatesSameIDAndRestoresOriginal(t *testing.T) {
	origin := originRecord
	origin.Proxied, origin.TTL = true, 300
	f := newFakeCF(t, origin)
	d, err := planDNS("token", testZone, origin.Name, "38.6.76.28")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.apply("token"); err != nil {
		t.Fatal(err)
	}
	records, writes := f.snapshot()
	if len(records) != 1 || d.Mode != "replaced" || d.After.ID != origin.ID || records[origin.ID].Content != "38.6.76.28" || records[origin.ID].Proxied || records[origin.ID].TTL != 300 {
		t.Fatalf("接管结果错误: %+v %+v", d, records)
	}
	if fmt.Sprint(writes) != "[PATCH:original-id]" {
		t.Fatal(writes)
	}
	if err := d.release("token"); err != nil {
		t.Fatal(err)
	}
	if err := d.release("token"); err != nil {
		t.Fatal("重复恢复应成功:", err)
	}
	records, writes = f.snapshot()
	if !sameRecord(records[origin.ID], origin) || fmt.Sprint(writes) != "[PATCH:original-id PATCH:original-id]" {
		t.Fatalf("未恢复原记录: %+v %v", records, writes)
	}
}

func TestCreatedAndReusedRecordsHaveDifferentCleanup(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			var f *fakeCF
			if existing {
				rec := originRecord
				rec.Content = "38.6.76.28"
				f = newFakeCF(t, rec)
			} else {
				f = newFakeCF(t)
			}
			d, err := planDNS("token", testZone, originRecord.Name, "38.6.76.28")
			if err != nil {
				t.Fatal(err)
			}
			if err = d.apply("token"); err != nil {
				t.Fatal(err)
			}
			if err = d.release("token"); err != nil {
				t.Fatal(err)
			}
			records, writes := f.snapshot()
			if existing && (len(records) != 1 || len(writes) != 0) {
				t.Fatalf("误动复用记录: %v %v", records, writes)
			}
			if !existing && (len(records) != 0 || fmt.Sprint(writes) != "[POST:new-id DELETE:new-id]") {
				t.Fatalf("新建记录未清理: %v %v", records, writes)
			}
		})
	}
}

func TestPreflightFailureNeverWritesDNS(t *testing.T) {
	for _, scenario := range []string{"查询失败", "多A", "AAAA", "CNAME"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFakeCF(t, originRecord)
			f.mu.Lock()
			if scenario == "查询失败" {
				f.failList = true
			} else {
				rec := originRecord
				rec.ID = "other"
				rec.Type = map[string]string{"多A": "A", "AAAA": "AAAA", "CNAME": "CNAME"}[scenario]
				f.records[rec.ID] = rec
			}
			f.mu.Unlock()
			if _, err := planDNS("token", testZone, originRecord.Name, "38.6.76.28"); err == nil {
				t.Fatal("应拒绝不明确的解析")
			}
			_, writes := f.snapshot()
			if len(writes) != 0 {
				t.Fatal(writes)
			}
		})
	}
}

func TestExternalDNSChangeIsPreserved(t *testing.T) {
	f := newFakeCF(t, originRecord)
	d, err := planDNS("token", testZone, originRecord.Name, "38.6.76.28")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.apply("token"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	edited := f.records[originRecord.ID]
	edited.Content = "192.0.2.10"
	f.records[edited.ID] = edited
	f.mu.Unlock()
	if err = d.release("token"); err == nil {
		t.Fatal("应报告外部修改冲突")
	}
	records, writes := f.snapshot()
	if records[edited.ID].Content != edited.Content || len(writes) != 1 {
		t.Fatal(records, writes)
	}
}

func TestUpstreamLoopRejected(t *testing.T) {
	for _, upstream := range []string{"https://redvpn.example.com", "https://REDVPN.EXAMPLE.COM.", "https://38.6.76.28", "http://127.0.0.1", "http://[::1]"} {
		if err := validateRelayUpstream(originRecord.Name, upstream, "38.6.76.28"); err == nil {
			t.Fatal("应拒绝自循环:", upstream)
		}
	}
	if err := validateRelayUpstream(originRecord.Name, "https://23.95.8.179", "38.6.76.28"); err != nil {
		t.Fatal(err)
	}
}
