package metrics

import (
	"github.com/gin-gonic/gin"
	"github.com/macrat/lauth/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type LogContext struct {
	Method      string
	Path        string
	Remote      string
	Err         error
	Error       string
	Description string
	Latency     float64
	timer       *prometheus.Timer
}

func StartLogging(ctx *gin.Context) *LogContext {
	c := &LogContext{
		Method: ctx.Request.Method,
		Path:   ctx.Request.URL.Path,
		Remote: ctx.ClientIP(),
	}
	c.timer = prometheus.NewTimer(c)

	return c
}

func (c *LogContext) writeLog(e *zerolog.Event) *zerolog.Event {
	e.Str("method", c.Method)
	e.Str("path", c.Path)
	e.Str("remote_addr", c.Remote)

	if c.Error != "" {
		e.Err(c.Err)
		e.Str("error", c.Error)
		e.Str("error_description", c.Description)
	}

	return e
}

func (c *LogContext) Observe(v float64) {
	c.Latency = v

	if c.Error != "" {
		c.writeLog(log.Error()).
			Float64("latency_seconds", c.Latency).
			Send()
	} else {
		c.writeLog(log.Info()).
			Float64("latency_seconds", c.Latency).
			Send()
	}
}

func (c *LogContext) Close() error {
	c.timer.ObserveDuration()
	c.timer = nil

	return nil
}

func (c *LogContext) SetError(err error) {
	if e, ok := err.(*errors.Error); ok {
		c.Err = e.Err
		c.Error = e.Reason.String()
		c.Description = e.Description
	} else {
		c.Err = err
		c.Error = errors.ServerError.String()
	}
}
