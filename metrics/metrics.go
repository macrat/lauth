package metrics

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	NAMESPACE = "lauth"
)

type ErrorReporter interface {
	SetError(err error, reason, description string)
}

type EndpointMetrics struct {
	Name        string
	Labels      []string
	TimerLabels []string
	Latency     *prometheus.SummaryVec
	Count       *prometheus.CounterVec
}

func NewEndpointMetrics(name string, labels []string, timerLabels []string) *EndpointMetrics {
	labels = append(labels, "status", "error", "error_description")
	timerLabels = append(timerLabels, "error")

	return &EndpointMetrics{
		Name:        name,
		Labels:      labels,
		TimerLabels: timerLabels,
		Latency: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: NAMESPACE,
				Subsystem: name,
				Name:      "seconds",
				Help:      fmt.Sprintf("The latency to processes the %s endpoint.", name),
			},
			timerLabels,
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
	Error   error
	Metrics *EndpointMetrics
	Labels  prometheus.Labels
	Method  string
	Path    string
	Remote  string
	timer   *prometheus.Timer
}

func (em *EndpointMetrics) Start(ctx *gin.Context) *Context {
	ls := make(prometheus.Labels)
	for _, l := range em.Labels {
		ls[l] = ""
	}
	c := &Context{
		Metrics: em,
		Labels:  ls,
		Method:  ctx.Request.Method,
		Path:    ctx.Request.URL.Path,
		Remote:  ctx.ClientIP(),
	}
	c.timer = prometheus.NewTimer(c)
	return c
}

func (c *Context) Set(key, value string) {
	c.Labels[key] = value
}

func (c *Context) SetError(err error, reason, description string) {
	c.Error = err
	c.Labels["error"] = reason
	c.Labels["error_description"] = description
}

// Success is succeed process and done.
func (c *Context) Success() {
	c.Labels["status"] = "success"
}

// Continue is succeed process but not done.
func (c *Context) Continue() {
	c.Labels["status"] = "continue"
}

// UserError is invalid username or password or something.
func (c *Context) UserError() {
	c.Labels["status"] = "user_error"
}

// ClientError is client side error except UserError.
func (c *Context) ClientError() {
	c.Labels["status"] = "client_error"
}

// ServerError is internal server error.
func (c *Context) ServerError() {
	c.Labels["status"] = "server_error"
}

func (c *Context) Observe(v float64) {
	labels := make([]string, len(c.Metrics.TimerLabels))
	for i, l := range c.Metrics.TimerLabels {
		labels[i] = c.Labels[l]
	}
	c.Metrics.Latency.WithLabelValues(labels...).Observe(v)
}

func (c *Context) writeLog(e *zerolog.Event) *zerolog.Event {
	e.Str("method", c.Method)
	e.Str("path", c.Path)
	e.Str("remote_addr", c.Remote)
	e.Str("endpoint", c.Metrics.Name)

	for _, l := range c.Metrics.Labels {
		if l != "method" && c.Labels[l] != "" {
			e.Str(l, c.Labels[l])
		}
	}

	if c.Error != nil {
		e.Err(c.Error)
	}

	return e
}

func (c *Context) Close() error {
	if c.Labels["status"] == "" && c.Labels["error"] != "" {
		if c.Labels["error"] == "server_error" {
			c.ServerError()
		} else {
			c.ClientError()
		}
	}
	c.Metrics.Count.With(c.Labels).Inc()
	duration := c.timer.ObserveDuration()
	c.timer = nil

	if c.Labels["error"] != "" {
		c.writeLog(log.Error()).
			Float64("latency_seconds", duration.Seconds()).
			Send()
	} else {
		c.writeLog(log.Info()).
			Float64("latency_seconds", duration.Seconds()).
			Send()
	}

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
