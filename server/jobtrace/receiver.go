// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package jobtrace

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"google.golang.org/protobuf/encoding/protowire"
)

// DefaultMaxBodyBytes bounds an export request, before and after
// decompression.
const DefaultMaxBodyBytes = 4 << 20

// Receiver is an OTLP/HTTP trace receiver. It accepts POST /v1/traces in
// protobuf or JSON, and stores only spans of traces the Recorder started for
// a live job.
type Receiver struct {
	Recorder *Recorder
	Logger   logging.SimpleLogging
	// MaxBodyBytes overrides DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

func (rc *Receiver) maxBody() int64 {
	if rc.MaxBodyBytes > 0 {
		return rc.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

const (
	contentProtobuf = "application/x-protobuf"
	contentJSON     = "application/json"
)

func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/traces" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != contentProtobuf && ct != contentJSON {
		http.Error(w, "send application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > rc.maxBody() {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, rc.maxBody())
	switch r.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return
		}
		defer zr.Close()
		body = zr
	default:
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	// Read one byte past the limit to tell a full body from a cut one.
	b, err := io.ReadAll(io.LimitReader(body, rc.maxBody()+1))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "reading request body failed", http.StatusBadRequest)
		return
	}
	if int64(len(b)) > rc.maxBody() {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var spans []rawSpan
	if ct == contentJSON {
		spans, err = decodeJSON(b)
	} else {
		spans, err = decodeProtobuf(b)
	}
	if err != nil {
		http.Error(w, "the request is not a valid OTLP trace export", http.StatusBadRequest)
		return
	}
	res := rc.Recorder.ingest(spans)
	if (res.Rejected > 0 || res.Dropped > 0) && rc.Logger != nil {
		// Only counts are logged; span names and attributes can carry
		// sensitive values.
		rc.Logger.Debug("job trace receiver accepted=%d rejected=%d dropped=%d", res.Accepted, res.Rejected, res.Dropped)
	}
	writeExportResponse(w, ct, res)
}

// writeExportResponse answers with an ExportTraceServiceResponse. Spans
// that were not stored are reported as a partial success, which exporters
// log at most, rather than as an error they would retry.
func writeExportResponse(w http.ResponseWriter, ct string, res IngestResult) {
	notStored := int64(res.Rejected + res.Dropped)
	msg := ""
	switch {
	case res.Rejected > 0 && res.Dropped > 0:
		msg = "some spans belong to no running Atlantis job, and the job's trace is full"
	case res.Rejected > 0:
		msg = "spans belong to no running Atlantis job"
	case res.Dropped > 0:
		msg = "the job's trace is full"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	if ct == contentJSON {
		out := map[string]any{}
		if notStored > 0 {
			out["partialSuccess"] = map[string]string{"rejectedSpans": strconv.FormatInt(notStored, 10), "errorMessage": msg}
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	if notStored == 0 {
		return
	}
	var partial []byte
	partial = protowire.AppendTag(partial, 1, protowire.VarintType)
	partial = protowire.AppendVarint(partial, uint64(notStored)) // #nosec G115 -- a count, never negative
	partial = protowire.AppendTag(partial, 2, protowire.BytesType)
	partial = protowire.AppendString(partial, msg)
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, partial)
	_, _ = w.Write(out)
}

// Server serves a Receiver on a loopback port.
type Server struct {
	srv *http.Server
	ln  net.Listener
}

// Listen starts a receiver on 127.0.0.1 on a port the system picks, and
// points the recorder's trace context at it.
func Listen(rec *Recorder, logger logging.SimpleLogging) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listening for job traces: %w", err)
	}
	s := &Server{
		ln: ln,
		srv: &http.Server{
			Handler:           &Receiver{Recorder: rec, Logger: logger},
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       time.Minute,
			MaxHeaderBytes:    64 << 10,
		},
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && logger != nil {
			logger.Err("job trace receiver stopped: %s", err)
		}
	}()
	rec.SetEndpoint("http://" + ln.Addr().String())
	return s, nil
}

// Addr is the receiver's address.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Close stops the receiver.
func (s *Server) Close(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
