package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Write([]byte("home 0"))
	})

	srv := http.Server{
		Addr:    "0.0.0.0:3333",
		Handler: mux,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			if err == http.ErrServerClosed {
				log.Println("server shutdown gracefully")
			}
			log.Println(err.Error())
		}
	}()

	k := make(chan os.Signal, 5)
	signal.Notify(k, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

	<-k

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(10)*time.Second)
	defer cancel()

	srv.Shutdown(ctx)
}
