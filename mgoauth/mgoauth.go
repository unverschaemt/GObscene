// mongo-auth
package mgoauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
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

/*
* User represents a login entity
* can be encoded to json or decoded from json
 */
type User struct {
	Id       string   `json:"_id,omitempty" bson:"_id,omitempty"`
	Password string          `json:"password"`
	Mail     string          `json: "mail"`
	Alias    string          `json:"alias"`
	Roles    map[string]bool `json:"roles"`
}

func GetUserId(c *gin.Context) (id string) {
	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user := u.(*User)
		id = user.Id
	} else {
		id = ""
	}
	return
}

func NotLoggedIn(c *gin.Context) {
	c.String(http.StatusUnauthorized, "User not logged in!")
	c.Abort()
}

func NoPermission(c *gin.Context) {
	c.String(http.StatusUnauthorized, "No permission!")
	c.Abort()
}

func init() {
	gob.Register(&User{})
}

// middleware for role authentication.
// only users that are logged in and have the roles passed as arguments are granted access
func RequireRole(role string) gin.HandlerFunc {
	// var rm roleMap

	// for _, role := range roles {
	//	 rm[role] = true
	// }
	log.Println("RequireRole init")
	return func(c *gin.Context) {
		log.Println("RequireRole middleware...")
		user := &User{}

		session := sessions.Default(c)
		log.Println(session)

		if u := session.Get("user"); u != nil {
			user = u.(*User)
			log.Println(user)
			if !user.Roles[role] {
				NoPermission(c)
			} else {
				c.Next()
			}
		} else {
			//c.Redirect(http.StatusSeeOther, "/auth/view/login")
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
* Login validates the credentials by retrieving the passphrase for the given
* user and comparing it to the given one
* if login succeeds the user model stored in the database is returned
 */
func doLogin(actualUser *User, db *mgo.Database) (*User, error) {
	var err error = nil
	//log.Printf("actualUser: %v", actualUser)
	if actualUser.Id != "" && actualUser.Password != "" {
		expectedUser := &User{}
		err = db.C("users").Find(bson.M{"_id": actualUser.Id}).One(expectedUser)
		if err == nil && secureCompare(actualUser.Password, expectedUser.Password) {
			return expectedUser, nil
		} else {
			err = fmt.Errorf("User: %v, %s", actualUser, err)
		}
	} else {
		err = fmt.Errorf("No empty user id or password accepted!")
	}

	return nil, err
}

func PostLogin(c *gin.Context) {
	user := &User{}

	// be aware that any information sent by the client could be parsed
	// e.g information about roles. Therefore it is important to override
	// the user model
	c.BindWith(user, binding.JSON)
	log.Println(user)

	db := ginutil.GetDB(c)
	session := sessions.Default(c)
	user, err := doLogin(user, db)
	//	log.Printf("USER: %v", user)
	//	log.Printf("ERROR: %v", err)
	//	log.Printf("DB: %v", db)
	if err != nil {
		user = nil
	} else {
		// if user successfully logged in, attach user model to session
		session.Set("user", user)
		err = session.Save()
	}

	if err != nil {
		log.Println(err)
	}
	log.Println(session)
}

//auth required here
func GetLogin(c *gin.Context) {
	user := &User{}

	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user = u.(*User)
		c.JSON(http.StatusOK, user)
	} else {
		c.String(http.StatusUnauthorized, "User not logged in!")
	}

}

func PostRegister(c *gin.Context) {
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
