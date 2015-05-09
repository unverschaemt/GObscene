// mongo-auth
package mgoauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/unverschaemt/go-server/ginutil"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"log"
	"net/http"
)

/*
* User represents a login entity
* can be encoded to json or decoded from json
 */
type User struct {
	Id       string `json:"_id,omitempty" bson:"_id,omitempty"`
	Password string
	Alias    string
	Roles    []string
}

func MongoAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if userId := session.Get("UserId"); userId != nil {
			db := c.MustGet("db").(*mgo.Database)
			user := &User{}
			err := db.C("users").Find(bson.M{"_id": userId}).One(&user)
			if err != nil {
				c.Set("user", nil)
			} else {
				c.Set("user", user)
			}
		}
		c.Next()
	}
}

/*
* Login validates the credentials by retrieving the passphrase for the given
* user and comparing it to the given one
 */
func doLogin(username, password string, db *mgo.Database) (user *User, err error) {
	if username != "" && password != "" {
		user = &User{}
		//log.Printf("PW: %s, USER: %s", password, username)
		err := db.C("users").Find(bson.M{"_id": username}).One(user)
		if !(err == mgo.ErrNotFound) && secureCompare(password, user.Password) {
			return user, nil
		}
	}
	return nil, err
}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	givenSha := sha256.Sum256([]byte(given))
	actualSha := sha256.Sum256([]byte(actual))

	return subtle.ConstantTimeCompare(givenSha[:], actualSha[:]) == 1
}

//auth required here
func GetLogin(c *gin.Context) {
	user := &User{}

	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user = u.(*User)
		c.JSON(http.StatusOK, user)
		log.Println(user)
	} else {
		c.String(http.StatusUnauthorized, "User not logged in!")
	}

}

func PostLogin(c *gin.Context) {
	user := &User{}
	c.BindWith(user, binding.JSON)
	log.Println(user)
	db := ginutil.GetDB(c)
	session := sessions.Default(c)
	user, err := doLogin(user.Id, user.Password, db)
	if err != nil {
		log.Println(err)
	} else {
		session.Set("user", user)
	}
	session.Save()
	log.Println(session)
}

func PostRegister(c *gin.Context) {
	user := User{}
	c.BindWith(user, binding.JSON)
	log.Println(user)
	db := ginutil.GetDB(c)
	if db.C("users").FindId(user.Id).Limit(1).One(bson.M{}) == mgo.ErrNotFound {
		err := db.C("users").Insert(user)
		if err != nil {
			log.Panicln(err)
		}
	} else {
		c.String(http.StatusConflict, "UserID already in use.")
		return
	}
	c.String(http.StatusOK, "Registered.")
}
