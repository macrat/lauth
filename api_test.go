package main_test

import (
	"github.com/gin-gonic/gin"
)

func MakeTestRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.LoadHTMLGlob("html/*.tmpl")

	return router
}
