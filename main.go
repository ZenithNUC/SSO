package SSO

import (
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
	"log"
	"net/http"
	"time"
)

var srv *server.Server			// 授权服务
var mgr *manage.Manager			// 授权管理

func main(){
	time.Sleep(30 * time.Second)

	config.Setup()		// 数据库连接初始化

	session.Setup()

	mgr = manage.NewDefaultManager()
	mgr.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	mgr.MustTokenStorage(store.NewMemoryTokenStore())

	mgr.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"),jwt.SigningMethodHS512))
	clientStore := store.NewClientStore()
	for _,v := range config.Get().OAuth2.Client{		// 获取client配置
		clientStore.Set(v.ID, &models.Client{
			ID:     v.ID,
			Secret: v.Secret,
			Domain: v.Domain,
		})
	}
	mgr.MapClientStorage(clientStore)

	srv = server.NewServer(server.NewConfig(),mgr)
	srv.SetPasswordAuthorizationHandler(passwordAuthorizationHandler)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)
	srv.SetAuthorizeScopeHandler(authorizeScopeHandler)
	srv.SetInternalErrorHandler(internalErrorHandler)
}

/*
密码授权处理程序
*/
func passwordAuthorizationHandler(username, password string)(userID string, err error){
	var user model.User
	userID = user.GetUserIDByPwd(username,password)
	return
}

/*
用户授权处理程序
*/
func userAuthorizeHandler(w http.ResponseWriter,r *http.Request)(userID string,err error){
	v,_ := session.Get(r,"LoggedInUserID")
	if v == nil{
		if r.Form == nil{
			r.ParseForm()
		}
		session.Set(w,r,"RequestForm",r.Form)
		w.Header().Set("Location","/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	userID = v.(string)
	return
}

/*
根据client注册的scope
 */
func authorizeScopeHandler(w http.ResponseWriter, r *http.Request)(scope string,err error){
	if r.Form == nil{
		r.ParseForm()
	}
	s := config.ScopeFilter(r.Form.Get("client_id"),r.Form.Get("scope"))
	if s == nil{
		http.Error(w,"Invalid Scope",http.StatusBadRequest)
		return
	}
	scope = config.ScopeJoin(s)
	return
}

/*
内部错误处理程序
*/
func internalErrorHandler(err error)(re *errors.Response){
	log.Println("Internal Error:",err.Error())
	return
}