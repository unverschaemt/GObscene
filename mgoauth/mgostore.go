// mgostore
package mgoauth

import (
	"github.com/gorilla/sessions"
	"github.com/kidstuff/mongostore"
	"gopkg.in/mgo.v2"
)

import . "github.com/gin-gonic/contrib/sessions"

type MongoStore interface {
	Store
}

// size: maximum number of idle connections.
// network: tcp or udp
// address: host:port
// password: redis-password
// Keys are defined in pairs to allow key rotation, but the common case is to set a single
// authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for encryption. The
// encryption key can be set to nil or omitted in the last pair, but the authentication key
// is required in all pairs.
//
// It is recommended to use an authentication key with 32 or 64 bytes. The encryption key,
// if set, must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256 modes.
func NewMongoStore(c *mgo.Collection, maxAge int, ensureTTL bool, keyPairs ...[]byte) MongoStore {
	store := mongostore.NewMongoStore(c, maxAge, ensureTTL, keyPairs...)
	return &mongoStore{store}
}

type mongoStore struct {
	*mongostore.MongoStore
}

func (c *mongoStore) Options(options Options) {
	c.MongoStore.Options = &sessions.Options{
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
	}
}
