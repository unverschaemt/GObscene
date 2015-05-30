package mgoauth

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type jwtProvider struct {
	privateKey []byte
	publicKey  []byte
}

// SessionProvider provides user authentication via jwt tokens.
// generate public an private key:
// $ openssl genrsa -out uv.pem 1024 # the 1024 is the size of the key we are generating
// $ openssl rsa -in uv.rsa -pubout > uv.rsa.pub
func JWTProvider(privateKey []byte, publicKey []byte) Provider {
	// we need to register the user struct to store it in the session
	return &jwtProvider{privateKey, publicKey}
}

// UserId extracts the user id from the session and returns it as string
func (p *jwtProvider) UserId(c *gin.Context) (id string) {
	if token, err := parseToken(c, p.publicKey); err == nil {
		id = token.Claims["id"].(string)
	} else {
		id = ""
	}

	return
}

// User extracts the user struct from the session and returns a pointer to it
func (p *jwtProvider) User(c *gin.Context) (user *User) {
	if token, err := parseToken(c, p.publicKey); err == nil {
		user = &User{Id: token.Claims["id"].(string)}
	} else {
		user = nil
	}
	return
}

// Login saves the user struct to the session
func (p *jwtProvider) Login(c *gin.Context, user *User) {

	// Create a Token that will be signed with RSA 256
	token := jwt.New(jwt.GetSigningMethod("RS256"))

	/*
		{
			"typ":"JWT",
			"alg":"RS256"
		}
	*/

	token.Claims["id"] = user.Id
	// token.Claims["roles"] = user.Roles
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// The claims object allows you to store information in the actual token.
	tokenString, err := token.SignedString(p.privateKey)

	// tokenString Contains the actual token you should share with your client.
	if err != nil {
		c.Fail(http.StatusInternalServerError, err)
	} else {
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

func parseToken(c *gin.Context, publicKey []byte) (token *jwt.Token, err error) {
	token, err = jwt.ParseFromRequest(c.Request, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	if token.Valid {
		err = nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			err = fmt.Errorf("Malformed token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			err = fmt.Errorf("Token timed out")
		} else {
			err = fmt.Errorf("Couldn't handle this token:", err)
		}
	} else {
		err = fmt.Errorf("Couldn't handle this token:", err)
	}
	return
}
