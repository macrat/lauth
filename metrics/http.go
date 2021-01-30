package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	HTTPLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace: NAMESPACE,
			Subsystem: "http",
			Name:      "latency_seconds",
			Help:      "The whole latency of each endpoint. It is includes non-core process like minifying or compression.",
		},
		[]string{"method", "path", "status"},
	)
)

func init() {
	prometheus.MustRegister(HTTPLatency)
}

type ResponseCollcetor struct {
	Upstream http.ResponseWriter
	Code     int
}

func (w *ResponseCollcetor) Header() http.Header {
	return w.Upstream.Header()
}

func (w *ResponseCollcetor) Write(data []byte) (int, error) {
	return w.Upstream.Write(data)
}

func (w *ResponseCollcetor) WriteHeader(statusCode int) {
	w.Code = statusCode
	w.Upstream.WriteHeader(statusCode)
}

func (w *ResponseCollcetor) StatusClass() string {
	switch {
	case w.Code >= 500:
		return "5xx"
	case w.Code >= 400:
		return "4xx"
	case w.Code >= 300:
		return "3xx"
	case w.Code >= 200:
		return "2xx"
	case w.Code >= 100:
		return "1xx"
	default:
		return "unknown"
	}
}

func Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &ResponseCollcetor{
			Upstream: w,
		}

		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			HTTPLatency.WithLabelValues(r.Method, r.URL.Path, rc.StatusClass()).Observe(v)
		}))
		defer timer.ObserveDuration()

		handler.ServeHTTP(rc, r)
	})
}
