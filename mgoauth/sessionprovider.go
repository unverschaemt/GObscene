package mgoauth

import (
	"encoding/gob"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
)

type sessionProvider struct {
}

// SessionProvider provides user authentication via cookie sessions
func SessionProvider() Provider {
	// we need to register the user struct to store it in the session
	gob.Register(&User{})
	return &sessionProvider{}
}

// UserId extracts the user id from the session and returns it as string
func (p *sessionProvider) UserId(c *gin.Context) (id string) {
	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user := u.(*User)
		id = user.Id
	} else {
		id = ""
	}
	return
}

// User extracts the user struct from the session and returns a pointer to it
func (p *sessionProvider) User(c *gin.Context) (user *User) {
	session := sessions.Default(c)
	if u := session.Get("user"); u != nil {
		user = u.(*User)
	} else {
		user = &User{}
	}
	return
}

// Login saves the user struct to the session
func (p *sessionProvider) Login(c *gin.Context, user *User) {
	session := sessions.Default(c)
	// if user successfully logged in, attach user model to session
	session.Set("user", user)
	err := session.Save()
	if err != nil {
		c.Fail(http.StatusInternalServerError, err)
	} else {
		c.String(http.StatusOK, "User successfully logged in!")
	}
}
