package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.LoadHTMLFiles("client.tmpl")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "client.tmpl", gin.H{
			"isCallback": false,
		})
	})

	r.GET("/callback", func(c *gin.Context) {
		c.HTML(http.StatusOK, "client.tmpl", gin.H{
			"isCallback": true,
		})
	})

	r.GET("/exchange", func(c *gin.Context) {
		req := c.Request.URL.Query()

		resp, err := http.Post("http://localhost:8000/login/token", "application/x-www-form-urlencoded", strings.NewReader(req.Encode()))
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to fetch token endpoint: %s", err)
			return
		}
		defer resp.Body.Close()

		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			c.String(http.StatusInternalServerError, "failed to parse response of token endpoint: %s", err)
			return
		}

		c.HTML(http.StatusOK, "client.tmpl", gin.H{
			"response": data,
		})
	})

	r.Run(":3000")
}
