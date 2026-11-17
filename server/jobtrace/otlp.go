// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobtrace

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// Limits on what one span may carry. Longer values are cut.
const (
	maxNameLen     = 256
	maxKeyLen      = 128
	maxValueLen    = 1024
	maxAttributes  = 64
	maxArrayValues = 32
)

// allowedAttributes are the span attributes whose values are kept by
// default. They name resources, providers and modules, or describe timing
// and errors. Everything else, such as request URLs and response headers,
// which can carry signed download links, keeps only its key.
var allowedAttributes = map[string]bool{
	"opentofu.resource_instance.address": true,
	"opentofu.resource.address":          true,
	"opentofu.resource.type":             true,
	"opentofu.provider.address":          true,
	"opentofu.provider.source":           true,
	"opentofu.provider.version":          true,
	"opentofu.provider_instance.address": true,
	"opentofu.provider_config.address":   true,
	"opentofu.module.name":               true,
	"opentofu.module.source_type":        true,
	"opentofu.plan.mode":                 true,
	"opentofu.plan.refresh":              true,
	"opentofu.plan.plan_changes":         true,
	"opentofu.target_platform":           true,
	"http.request.method":                true,
	"http.response.status_code":          true,
	"server.address":                     true,
	"exception.type":                     true,
	"exception.message":                  true,
	"error.type":                         true,
	"span.kind":                          true,
}

// AllowedAttribute reports whether an attribute's value is kept by default.
func AllowedAttribute(key string) bool {
	return allowedAttributes[key]
}

// rawSpan is a span as decoded from OTLP, before it is stored.
type rawSpan struct {
	traceID [16]byte
	spanID  [8]byte
	parent  [8]byte
	name    string
	kind    int32
	start   uint64
	end     uint64
	attrs   []Attribute
	err     bool
	message string
	service string
}

// IngestResult says how many spans of a request were stored.
type IngestResult struct {
	Accepted int
	// Rejected spans belong to no trace Atlantis is collecting, or are
	// malformed.
	Rejected int
	// Dropped spans belonged to a trace that is full.
	Dropped int
}

// ingest stores spans of traces Atlantis started for live jobs and rejects
// the rest.
func (r *Recorder) ingest(spans []rawSpan) IngestResult {
	var res IngestResult
	if r == nil {
		res.Rejected = len(spans)
		return res
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rs := range spans {
		t := r.acceptingLocked(rs.traceID)
		if t == nil || rs.spanID == [8]byte{} {
			res.Rejected++
			continue
		}
		s := Span{
			ID:         hex.EncodeToString(rs.spanID[:]),
			Name:       truncate(rs.name, maxNameLen),
			Source:     truncate(rs.service, maxNameLen),
			Start:      fromUnixNano(rs.start),
			End:        fromUnixNano(max(rs.end, rs.start)),
			Error:      rs.err,
			Message:    truncate(rs.message, maxValueLen),
			Attributes: r.filter(rs.attrs, rs.kind),
		}
		if rs.parent != ([8]byte{}) {
			s.ParentID = hex.EncodeToString(rs.parent[:])
		}
		if i, ok := t.index[s.ID]; ok && t.spans[i].Source == "atlantis" {
			// A span may not replace one of Atlantis's own.
			res.Rejected++
			continue
		}
		if i, ok := t.index[s.ParentID]; ok && t.spans[i].Source == "atlantis" {
			// The root span of a process. Terraform names it after the whole
			// command line, which can hold variable values.
			s.Name = processName(s.Name)
		}
		s.Category = categorize(s)
		if r.addLocked(t, s) {
			res.Accepted++
		} else {
			res.Dropped++
		}
	}
	return res
}

// processName keeps the binary and subcommand words of a command line, such
// as "terraform plan" from "terraform plan -var x=y -out /tmp/p", and drops
// the arguments.
func processName(name string) string {
	var kept []string
	for f := range strings.FieldsSeq(name) {
		if len(kept) == 3 || !isWord(f) {
			break
		}
		kept = append(kept, f)
	}
	if len(kept) == 0 {
		return "process"
	}
	return strings.Join(kept, " ")
}

func isWord(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' && (r != '-' || s[0] == '-') {
			return false
		}
	}
	return s != ""
}

func fromUnixNano(ns uint64) time.Time {
	if ns > math.MaxInt64 {
		ns = math.MaxInt64
	}
	return time.Unix(0, int64(ns)).UTC()
}

// filter keeps allowlisted values and hides the others, unless every value
// is kept.
func (r *Recorder) filter(attrs []Attribute, kind int32) []Attribute {
	out := make([]Attribute, 0, min(len(attrs), maxAttributes)+1)
	if k := spanKind(kind); k != "" {
		out = append(out, Attribute{Key: "span.kind", Value: k})
	}
	for _, a := range attrs {
		if len(out) >= maxAttributes {
			break
		}
		a.Key = truncate(a.Key, maxKeyLen)
		if !r.AllAttributes && !allowedAttributes[a.Key] {
			a.Value, a.Hidden = "", true
		} else {
			a.Value = truncate(a.Value, maxValueLen)
		}
		out = append(out, a)
	}
	slices.SortStableFunc(out, func(a, b Attribute) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func spanKind(k int32) string {
	switch tracepb.Span_SpanKind(k) {
	case tracepb.Span_SPAN_KIND_INTERNAL:
		return "internal"
	case tracepb.Span_SPAN_KIND_SERVER:
		return "server"
	case tracepb.Span_SPAN_KIND_CLIENT:
		return "client"
	case tracepb.Span_SPAN_KIND_PRODUCER:
		return "producer"
	case tracepb.Span_SPAN_KIND_CONSUMER:
		return "consumer"
	}
	return ""
}

// categorize sorts a reported span into resource, provider, or other tool
// work.
func categorize(s Span) Category {
	has := func(keys ...string) bool {
		for _, a := range s.Attributes {
			if slices.Contains(keys, a.Key) {
				return true
			}
		}
		return false
	}
	switch {
	case has("opentofu.resource_instance.address", "opentofu.resource.address"):
		return CategoryResource
	case has("opentofu.provider.address", "opentofu.provider.source", "opentofu.provider_instance.address", "opentofu.provider_config.address"),
		strings.Contains(strings.ToLower(s.Name), "provider"):
		return CategoryProvider
	}
	return CategoryTool
}

// decodeProtobuf reads an ExportTraceServiceRequest. It has the same wire
// format as TracesData, which avoids depending on the gRPC service package.
func decodeProtobuf(body []byte) ([]rawSpan, error) {
	var td tracepb.TracesData
	if err := proto.Unmarshal(body, &td); err != nil {
		return nil, fmt.Errorf("decoding protobuf: %w", err)
	}
	var out []rawSpan
	for _, rs := range td.GetResourceSpans() {
		service := ""
		for _, kv := range rs.GetResource().GetAttributes() {
			if kv.GetKey() == "service.name" {
				service = kv.GetValue().GetStringValue()
			}
		}
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				r := rawSpan{
					name:    sp.GetName(),
					kind:    int32(sp.GetKind()),
					start:   sp.GetStartTimeUnixNano(),
					end:     sp.GetEndTimeUnixNano(),
					service: service,
				}
				if !copyID(r.traceID[:], sp.GetTraceId()) || !copyID(r.spanID[:], sp.GetSpanId()) {
					r.traceID, r.spanID = [16]byte{}, [8]byte{}
				}
				copyID(r.parent[:], sp.GetParentSpanId())
				for _, kv := range sp.GetAttributes() {
					r.attrs = append(r.attrs, Attribute{Key: kv.GetKey(), Value: protoValue(kv.GetValue(), 0)})
				}
				if sp.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR {
					r.err = true
					r.message = sp.GetStatus().GetMessage()
					if r.message == "" {
						r.message = protoExceptionMessage(sp.GetEvents())
					}
				}
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func copyID(dst, src []byte) bool {
	if len(src) != len(dst) {
		return false
	}
	copy(dst, src)
	return true
}

func protoExceptionMessage(events []*tracepb.Span_Event) string {
	for _, e := range events {
		if e.GetName() != "exception" {
			continue
		}
		for _, kv := range e.GetAttributes() {
			if kv.GetKey() == "exception.message" {
				return protoValue(kv.GetValue(), 0)
			}
		}
	}
	return ""
}

func protoValue(v *commonpb.AnyValue, depth int) string {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_ArrayValue:
		if depth > 2 {
			return "[…]"
		}
		var parts []string
		for i, e := range x.ArrayValue.GetValues() {
			if i >= maxArrayValues {
				parts = append(parts, "…")
				break
			}
			parts = append(parts, protoValue(e, depth+1))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *commonpb.AnyValue_KvlistValue:
		return "{…}"
	case *commonpb.AnyValue_BytesValue:
		return fmt.Sprintf("(%d bytes)", len(x.BytesValue))
	}
	return ""
}

// The OTLP/JSON encoding: field names are lowerCamelCase, IDs are hex, and
// 64-bit integers may be strings.

type jsonTraces struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []jsonKV `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []jsonSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type jsonSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId"`
	Name              string     `json:"name"`
	Kind              jsonNumber `json:"kind"`
	StartTimeUnixNano jsonNumber `json:"startTimeUnixNano"`
	EndTimeUnixNano   jsonNumber `json:"endTimeUnixNano"`
	Attributes        []jsonKV   `json:"attributes"`
	Status            struct {
		Code    jsonNumber `json:"code"`
		Message string     `json:"message"`
	} `json:"status"`
	Events []struct {
		Name       string   `json:"name"`
		Attributes []jsonKV `json:"attributes"`
	} `json:"events"`
}

type jsonKV struct {
	Key   string    `json:"key"`
	Value jsonValue `json:"value"`
}

type jsonValue struct {
	StringValue *string     `json:"stringValue"`
	BoolValue   *bool       `json:"boolValue"`
	IntValue    *jsonNumber `json:"intValue"`
	DoubleValue *float64    `json:"doubleValue"`
	ArrayValue  *struct {
		Values []jsonValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *json.RawMessage `json:"kvlistValue"`
	BytesValue  *string          `json:"bytesValue"`
}

// jsonNumber accepts a number or a string holding one, as OTLP/JSON encodes
// 64-bit integers either way. Enum values may also be given by name.
type jsonNumber string

func (n *jsonNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	*n = jsonNumber(s)
	return nil
}

func (n jsonNumber) uint64() uint64 {
	v, _ := strconv.ParseUint(string(n), 10, 64)
	return v
}

func (n jsonNumber) int64() int64 {
	v, _ := strconv.ParseInt(string(n), 10, 64)
	return v
}

func (v jsonValue) String(depth int) string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	case v.IntValue != nil:
		return strconv.FormatInt(v.IntValue.int64(), 10)
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	case v.ArrayValue != nil:
		if depth > 2 {
			return "[…]"
		}
		var parts []string
		for i, e := range v.ArrayValue.Values {
			if i >= maxArrayValues {
				parts = append(parts, "…")
				break
			}
			parts = append(parts, e.String(depth+1))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case v.KvlistValue != nil:
		return "{…}"
	case v.BytesValue != nil:
		return "(bytes)"
	}
	return ""
}

func decodeJSON(body []byte) ([]rawSpan, error) {
	var td jsonTraces
	if err := json.Unmarshal(body, &td); err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}
	var out []rawSpan
	for _, rs := range td.ResourceSpans {
		service := ""
		for _, kv := range rs.Resource.Attributes {
			if kv.Key == "service.name" {
				service = kv.Value.String(0)
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				r := rawSpan{
					name:    sp.Name,
					kind:    int32(sp.Kind.int64()), // #nosec G115 -- span kinds are small enum values; anything else is ignored
					start:   sp.StartTimeUnixNano.uint64(),
					end:     sp.EndTimeUnixNano.uint64(),
					service: service,
				}
				if !hexID(r.traceID[:], sp.TraceID) || !hexID(r.spanID[:], sp.SpanID) {
					r.traceID, r.spanID = [16]byte{}, [8]byte{}
				}
				hexID(r.parent[:], sp.ParentSpanID)
				for _, kv := range sp.Attributes {
					r.attrs = append(r.attrs, Attribute{Key: kv.Key, Value: kv.Value.String(0)})
				}
				if code := string(sp.Status.Code); code == "2" || code == "STATUS_CODE_ERROR" {
					r.err = true
					r.message = sp.Status.Message
					if r.message == "" {
						for _, e := range sp.Events {
							if e.Name != "exception" {
								continue
							}
							for _, kv := range e.Attributes {
								if kv.Key == "exception.message" {
									r.message = kv.Value.String(0)
								}
							}
						}
					}
				}
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func hexID(dst []byte, s string) bool {
	if hex.DecodedLen(len(s)) != len(dst) {
		return false
	}
	_, err := hex.Decode(dst, []byte(s))
	return err == nil
}
