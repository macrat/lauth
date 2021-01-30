package metrics

var (
	Userinfo = NewEndpointMetrics("userinfo", []string{"scope"})
)

func init() {
	Userinfo.MustRegister()
}

func StartUserinfo() *Context {
	return Userinfo.Start()
}
