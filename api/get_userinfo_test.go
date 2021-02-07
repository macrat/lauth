package api_test

import (
	"testing"

	"github.com/macrat/lauth/testutil"
)

func TestGetUserInfo(t *testing.T) {
	env := testutil.NewAPITestEnvironment(t)

	env.JSONTest(t, "GET", "/userinfo", UserInfoCommonTests(t, env))
}
