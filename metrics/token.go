package metrics

var (
	Token = NewEndpointMetrics("token", []string{"client_id", "grant_type", "scope"})
)

func init() {
	Token.MustRegister()
}

func StartPostToken() *Context {
	return Token.Start()
}
