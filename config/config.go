package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

var cfg App

func Setup()  {
	content,err := ioutil.ReadFile("app.yaml")
	if err != nil{
		log.Fatalf("error: %v", err)
	}
	err = yaml.Unmarshal(content,&cfg)
	if err != nil{
		log.Fatalf("error: %v", err)
	}
}