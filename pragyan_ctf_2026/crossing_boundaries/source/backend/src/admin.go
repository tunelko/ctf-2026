package app

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *App) adminFlag(w http.ResponseWriter, r *http.Request) {
	s := a.getSession(r)
	if s == nil || s.Username != adminUsername {
		http.Error(w, "You are not admin. Are you?", 401)
		return
	}

	w.Write([]byte(a.Config.Flag))
}

func (a *App) triggerAdminReview(blogID string, userSession string) {
	time.Sleep(10 * time.Second)

	req, _ := http.NewRequest(
		"GET",
		a.Config.UpstreamAddr+"/admin/blogs/"+blogID,
		nil,
	)

	req.Header.Add("X-User-Session", userSession)

	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: a.Config.AdminSessionID,
	})

	req.Header.Set("User-Agent", "AdminBot/1.0")

	resp, err := a.Client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		_, err = a.DB.Exec(
			"INSERT INTO reviews VALUES (?, ?, ?, ?)",
			uuid.New().String(),
			blogID,
			"Good blog!",
			time.Now().UnixMilli(),
		)
	}

	if err != nil {
		log.Printf("Admin review failed for %s: %v", blogID, err)
		return
	}

	log.Printf("Admin review %s -> %s", blogID, resp.Status)
}


func (a *App) adminPublicBlog(w http.ResponseWriter, r *http.Request) {
	s := a.getSession(r)
	if s == nil || s.Username != adminUsername {
		http.Error(w, "You are not admin. Are you?", 401)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/admin/blogs/")

	var owner, content string
	var pub, timestamp int64
	a.DB.QueryRow(
		"SELECT owner, content, is_published, timestamp FROM blogs WHERE blog_id=?",
		id,
	).Scan(&owner, &content, &pub, &timestamp)

	body := fmt.Sprintf(`
<a href="/">Back</a>
<h2>Our Blog</h2>
<pre>%s</pre>
<hr>
<strong>Date:</strong> %s<br>
<strong>Status:</strong> %s<br>
`, content, time.UnixMilli(timestamp).UTC().String()[0:19] + " UTC", "Published")

	a.renderPage(r, w, "Public Blog", body, true)
}
