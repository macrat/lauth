package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	NAMESPACE = "ldapin"
)

type EndpointMetrics struct {
	Labels  []string
	Latency *prometheus.SummaryVec
	Count   *prometheus.CounterVec
}

func NewEndpointMetrics(name string, labels []string) *EndpointMetrics {
	labels = append(labels, "error", "error_description", "status")

	return &EndpointMetrics{
		Labels: labels,
		Latency: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: NAMESPACE,
				Subsystem: name,
				Name:      "seconds",
				Help:      fmt.Sprintf("The latency to processes the %s endpoint.", name),
			},
			labels,
		),
		Count: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: NAMESPACE,
				Subsystem: name,
				Name:      "count",
				Help:      fmt.Sprintf("The count of use the %s endpoint.", name),
			},
			labels,
		),
	}
}

func (em *EndpointMetrics) MustRegister() {
	prometheus.MustRegister(em.Latency)
	prometheus.MustRegister(em.Count)
}

type Context struct {
	Metrics *EndpointMetrics
	Labels  prometheus.Labels
	timer   *prometheus.Timer
}

func (em *EndpointMetrics) Start() *Context {
	ls := make(prometheus.Labels)
	for _, l := range em.Labels {
		ls[l] = ""
	}
	c := &Context{
		Metrics: em,
		Labels:  ls,
	}
	c.timer = prometheus.NewTimer(c)
	return c
}

func (c *Context) Set(key, value string) {
	c.Labels[key] = value
}

func (c *Context) Observe(v float64) {
	c.Metrics.Latency.With(c.Labels).Observe(v)
}

func (c *Context) Close() error {
	switch c.Labels["error"] {
	case "":
		c.Labels["status"] = "2xx"
	case "server_error":
		c.Labels["status"] = "5xx"
	default:
		c.Labels["status"] = "4xx"
	}
	c.Metrics.Count.With(c.Labels).Inc()
	c.timer.ObserveDuration()
	c.timer = nil
	return nil
}

func Handler(username, password string) http.Handler {
	handler := promhttp.Handler()
	if username == "" {
		return handler
	} else {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != username || p != password {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Prometheus Metrics\"")
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				handler.ServeHTTP(w, r)
			}
		})
	}
}
