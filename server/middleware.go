// Copyright 2017 HootSuite Media Inc.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Modified hereafter by contributors to runatlantis/atlantis.

package server

import (
	"net/http"
	"strings"

	"github.com/cloudposse/atlantis/server/logging"
	"github.com/urfave/negroni"
)

// NewRequestLogger creates a RequestLogger.
func NewRequestLogger(logger *logging.SimpleLogger) *RequestLogger {
	return &RequestLogger{logger}
}

// RequestLogger logs requests and their response codes.
type RequestLogger struct {
	logger *logging.SimpleLogger
}

// ServeHTTP implements the middleware function. It logs a request at INFO
// level unless it's a request to /static/*.
func (l *RequestLogger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(rw, r)
	res := rw.(negroni.ResponseWriter)
	if !strings.HasPrefix(r.URL.RequestURI(), "/static") {
		l.logger.Info("%d | %s %s", res.Status(), r.Method, r.URL.RequestURI())
	}
}
