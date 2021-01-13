package config

import "strings"

func Get() *App{
	return &cfg
}

func GetClient(clientID string)(cli Client){
	for _,v := range cfg.OAuth2.Client {
		if v.ID == clientID{
			cli = v
		}
	}
	return
}

func ScopeJoin(scope []Scope) string{
	var s []string
	for _,sc := range scope{
		s = append(s,sc.ID)
	}
	return strings.Join(s,",")
}