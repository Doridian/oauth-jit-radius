package main

import (
	"html/template"
	"log"
	"net/http"
)

var templates = buildTemplates()

func buildTemplates() *template.Template {
	tpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		panic(err)
	}
	return tpl
}

type tplData struct {
	Data interface{}
	Req  *http.Request
}

func RenderTemplate(wr http.ResponseWriter, r *http.Request, name string, data interface{}) {
	err := templates.ExecuteTemplate(wr, name, &tplData{Req: r, Data: data})
	if err != nil {
		http.Error(wr, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Error rendering template: %v", err)
		return
	}
}
