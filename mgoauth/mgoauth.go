// mongo-auth
package mgoauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/unverschaemt/gobscene/ginutil"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"log"
	"net/http"
)

const (
	ADMIN   = "admin"
	DEFAULT = "default"
)

type Authenticator struct {
	Provider
}

type Provider interface {
	// UserId returns the user id if a user is logged in or an empty string else
	UserId(c *gin.Context) string

	// User returns the user struct if a user is logged in or nil else
	User(c *gin.Context) *User

	// Login handels a login request
	Login(c *gin.Context, user *User)
}

/*
* User represents a login entity
* can be encoded to json or decoded from json
 */
type User struct {
	Id       string          `json:"_id,omitempty" bson:"_id,omitempty"`
	Password string          `json:"password"`
	Mail     string          `json:"mail"`
	Alias    string          `json:"alias"`
	Roles    map[string]bool `json:"roles"`
}

func New(p Provider) *Authenticator {
	return &Authenticator{p}
}

func NotLoggedIn(c *gin.Context) {
	c.String(http.StatusUnauthorized, "User not logged in!")
	c.Abort()
}

func NoPermission(c *gin.Context) {
	c.String(http.StatusUnauthorized, "No permission!")
	c.Abort()
}

// middleware for role authentication.
// only users that are logged in and have the roles passed as arguments are granted access
func (a *Authenticator) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("RequireRole middleware...")
		if user := a.User(c); user != nil {
			log.Println(user)
			if !user.Roles[role] {
				NoPermission(c)
			} else {
				c.Next()
			}
		} else {
			NotLoggedIn(c)
		}
	}
}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	givenSha := sha256.Sum256([]byte(given))
	actualSha := sha256.Sum256([]byte(actual))

	return subtle.ConstantTimeCompare(givenSha[:], actualSha[:]) == 1
}

/*
* doLogin validates the credentials by retrieving the passphrase for the given
* user and comparing it to the given one
* if login succeeds the user model stored in the database is returned
 */
func doLogin(actualUser *User, db *mgo.Database) (*User, error) {
	var err error = nil
	if actualUser.Id != "" && actualUser.Password != "" {
		expectedUser := &User{}
		err = db.C("users").Find(bson.M{"_id": actualUser.Id}).One(expectedUser)
		if err == nil && secureCompare(actualUser.Password, expectedUser.Password) {
			return expectedUser, nil
		} else {
			err = fmt.Errorf("mgoauth: Login failed %v", *actualUser)
		}
	} else {
		err = fmt.Errorf("mgoauth: No empty user id or password accepted!")
	}
	return nil, err
}

func (a *Authenticator) PostLogin(c *gin.Context) {
	user := &User{}
	// be aware that any information sent by the client could be parsed
	// e.g information about roles. Therefore it is important to override
	// the user model
	c.BindWith(user, binding.JSON)
	log.Println(user)

	db := ginutil.GetDB(c)
	user, err := doLogin(user, db)
	if err != nil {
		c.Fail(http.StatusUnauthorized, err)
	} else {
		a.Login(c, user)
	}
}

func (a *Authenticator) GetLogin(c *gin.Context) {
	user := &User{}

	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user = u.(*User)
		c.JSON(http.StatusOK, user)
	} else {
		c.String(http.StatusUnauthorized, "User not logged in!")
	}
}

func (a *Authenticator) PostRegister(c *gin.Context) {
	user := &User{}
	if c.BindWith(user, binding.JSON) {
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
}
