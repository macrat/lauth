package metrics

var (
	Authz = NewEndpointMetrics("authz", []string{"method", "response_type", "client_id", "scope", "prompt", "authn_by"})
)

func init() {
	Authz.MustRegister()
}

func StartAuthz(method string) *Context {
	c := Authz.Start()
	c.Set("method", method)
	return c
}

func StartGetAuthz() *Context {
	return StartAuthz("GET")
}

func StartPostAuthz() *Context {
	return StartAuthz("POST")
}
