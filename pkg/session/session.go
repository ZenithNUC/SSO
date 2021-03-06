package session

import (
	"com.sso.zenith/config"
	"encoding/gob"
	"github.com/gorilla/sessions"
	"net/http"
	"net/url"
)

var store *sessions.CookieStore

func Setup(){
	gob.Register(url.Values{})
	store = sessions.NewCookieStore([]byte(config.Get().Session.SecretKey))
	store.Options = &sessions.Options{
		Path: "/",
		MaxAge: 60*20,
		HttpOnly: true,
	}
}

func Get(r *http.Request,name string) (val interface{},err error){
	session,err := store.Get(r,config.Get().Session.Name)
	if err != nil{
		return
	}
	val = session.Values[name]
	return
}

func Set(w http.ResponseWriter,r *http.Request,name string,val interface{}) (err error){
	session,err := store.Get(r,config.Get().Session.Name)
	if err != nil {
		return
	}
	session.Values[name] = val
	err = session.Save(r,w)
	return
}

func Delete(w http.ResponseWriter,r *http.Request,name string) (err error){
	session,err := store.Get(r,config.Get().Session.Name)
	if err != nil{
		return
	}
	delete(session.Values,name)
	err = session.Save(r,w)
	return
}