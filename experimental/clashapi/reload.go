//go:build !android && !ios

package clashapi

import (
	"net/http"

	"github.com/go-chi/render"
)

func reload(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			server.logger.Warn("box restarting...")
			server.router.Reload()
		}()
		render.NoContent(w, r)
	}
}
