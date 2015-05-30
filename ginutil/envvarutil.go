package ginutil

import (
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
)

func GetDB(c *gin.Context) *mgo.Database {
	db := c.MustGet("db")
	return db.(*mgo.Database)
}

func SetEnvvar(key string, value interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(key, value)
	}
}
