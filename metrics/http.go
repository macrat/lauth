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
			Name:      "latency",
			Help:      "The whole latency of each endpoint. It is includes non-core process like minifying or compression.",
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(HTTPLatency)
}

func Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			HTTPLatency.WithLabelValues(r.Method, r.URL.Path).Observe(v)
		}))
		defer timer.ObserveDuration()

		handler.ServeHTTP(w, r)
	})
}
