package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"com.sso.zenith/config"
	"com.sso.zenith/model"
	"com.sso.zenith/pkg/session"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/generates"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

var srv *server.Server  // 授权服务
var mgr *manage.Manager // 授权管理

type TplData struct {
	Client config.Client
	Scope  []config.Scope
	Error  string
}

func main() {
	time.Sleep(30 * time.Second)

	config.Setup() // 数据库连接初始化

	session.Setup()

	mgr = manage.NewDefaultManager()
	mgr.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	mgr.MustTokenStorage(store.NewMemoryTokenStore())

	mgr.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))
	clientStore := store.NewClientStore()
	for _, v := range config.Get().OAuth2.Client { // 获取client配置
		clientStore.Set(v.ID, &models.Client{
			ID:     v.ID,
			Secret: v.Secret,
			Domain: v.Domain,
		})
	}
	mgr.MapClientStorage(clientStore)

	// 设置oauth2服务
	srv = server.NewServer(server.NewConfig(), mgr)
	srv.SetPasswordAuthorizationHandler(passwordAuthorizationHandler)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)
	srv.SetAuthorizeScopeHandler(authorizeScopeHandler)
	srv.SetInternalErrorHandler(internalErrorHandler)
	srv.SetResponseErrorHandler(responseErrorHandler)

	// 设置http服务
	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/test", testHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}

/*
密码授权处理程序
*/
func passwordAuthorizationHandler(username, password string) (userID string, err error) {
	var user model.User
	userID = user.GetUserIDByPwd(username, password)
	return
}

/*
用户授权处理程序
*/
func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	v, _ := session.Get(r, "LoggedInUserID")
	if v == nil {
		if r.Form == nil {
			r.ParseForm()
		}
		session.Set(w, r, "RequestForm", r.Form)
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	userID = v.(string)
	return
}

/*
根据client注册的scope
*/
func authorizeScopeHandler(w http.ResponseWriter, r *http.Request) (scope string, err error) {
	if r.Form == nil {
		r.ParseForm()
	}
	s := config.ScopeFilter(r.Form.Get("client_id"), r.Form.Get("scope"))
	if s == nil {
		http.Error(w, "Invalid Scope", http.StatusBadRequest)
		return
	}
	scope = config.ScopeJoin(s)
	return
}

/*
内部错误处理程序
*/
func internalErrorHandler(err error) (re *errors.Response) {
	log.Println("Internal Error:", err.Error())
	return
}

/*
响应错误处理程序
*/
func responseErrorHandler(re *errors.Response) {
	log.Println("ResponseError:", re.Error.Error())
}

/*
授权程序
*/
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	var form url.Values
	v, _ := session.Get(r, "RequestForm")
	if v != nil {
		r.ParseForm()
		if r.Form.Get("client_id") == "" {
			form = v.(url.Values)
		}
	}
	r.Form = form

	err := session.Delete(w, r, "RequestForm")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

/*
登录处理
*/
func loginHandler(w http.ResponseWriter, r *http.Request) {
	form, err := session.Get(r, "RequestForm")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if form == nil {
		http.Error(w, "Invalid Request", http.StatusBadRequest)
		return
	}
	clientID := form.(url.Values).Get("client_id")
	scope := form.(url.Values).Get("scope")

	data := TplData{
		Client: config.GetClient(clientID),
		Scope:  config.ScopeFilter(clientID, scope),
	}

	if data.Scope == nil {
		http.Error(w, "Invalid Scope", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		err = r.ParseForm()
		if r.Form == nil {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		var userID string

		if r.Form.Get("type") == "password" {
			var user model.User
			userID = user.GetUserIDByPwd(r.Form.Get("username"), r.Form.Get("password"))
			if userID == "" {
				t, err := template.ParseFiles("tpl/login.html")
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				data.Error = "用户名或密码错误"
				t.Execute(w, data)

				return
			}
		}

		err = session.Set(w, r, "LoggedInUserID", userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", "authorize")
		w.WriteHeader(http.StatusFound)
		return
	}
	t, err := template.ParseFiles("tpl/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Form == nil {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	redirectURI := r.Form.Get("redirect_uri")
	_, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	err = session.Delete(w, r, "LoggedinUserID")
	if err != nil { // ID没有登录
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	err := srv.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	token, err := srv.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cli, err := mgr.GetClient(token.GetClientID())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data := map[string]interface{}{
		"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		"user_id":    token.GetUserID(),
		"client_id":  token.GetClientID(),
		"scope":      token.GetScope(),
		"domain":     cli.GetDomain(),
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(data)
}
