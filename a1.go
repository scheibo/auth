package a1

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/didip/tollbooth/limiter"
	"github.com/gorilla/securecookie"
	"github.com/tdewolff/minify"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/xsrftoken"
)

const LoginPath = "/login"
const LogoutPath = "/logout"
const RedirectPath = "/"

type Client struct {
	hash []byte

	session *Session
	cookie  securecookie.SecureCookie

	xsrfKey  string
	hashKey  []byte
	blockKey []byte
}

type Session struct {
	id      string
	expires time.Time
}

func Hash(password string) (string, error) {
	sha := sha512.Sum512([]byte(password))
	bytes, err := bcrypt.GenerateFromPassword(sha, bcrypt.DefaultCost)
	return string(bytes), err
}

func New(hash string) *Client {
	return &Client{
		hash:     []byte(hash),
		xsrfKey:  string(generateKey()),
		hashKey:  generateKey(),
		blockKey: generateKey(),
	}
}

func (c *Client) LoginPage(path ...string) *http.Handler {
	return CustomLoginPage("https://raw.githubusercontent.com/scheibo/auth/master/favicon.png", "Login")
}

func (c *Client) CustomLoginPage(favicon, title string, path ...string) *http.Handler {
	return &http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHTTPS(r) {
			httpError(w, 500, errors.New("login page must be served over HTTPS"))
		}

		loginPath := LoginPath
		if len(path) > 0 && path[0] != "" {
			loginPath = path[0]
		}

		t := template.Must(compileTemplates("login.html"))
		t.Execute(w, struct {
			Favicon string
			Title   string
			Path    string
			Token   string
		}{
			favicon, title, loginPath, c.XSRF(loginPath),
		})
	})
}

func RateLimit(handler *httpHandler, qps float64) *http.Handler {
	return &tollbooth.LimitFuncHandler(tollbooth.NewLimiter(qps, nil), handler)
}

func (c *Client) Login(paths ...string) *http.Handler {
	loginPath, redirectPath := LoginPath, RedirectPath
	if len(path) >= 1 {
		if path[0] != "" {
			loginPath = path[0]
		}
		if len(path) > 1 && path[1] != "" {
			redirectPath = path[1]
		}
	}

	return RateLimit(c.CheckXRSF(&http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isHTTPS(r) {
			httpError(w, 500, errors.New("login request must be over HTTPS"))
		}
		if r.Method != "POST" {
			httpError(w, 500, errors.New("login request must use POST"))
		}

		var password, token = r.PostFormValue("password")
		sha := sha512.Sum512([]byte(password))
		err := bcrypt.CompareHashAndPassword(hash, sha)
		if err != nil {
			httpError(w, 401, err)
			return
		}

		c.session = &Session{
			id:      string(generateKey()),
			expires: time.Now().AddDate(0, 0, 30),
		}
		cookie, err := c.newCookie()
		if err != nil {
			httpError(w, 500, err)
			return
		}
		http.SetCookie(w, cookie)

		http.Redirect(w, r, redirectPath, 302)
	}), loginPath), 1)
}

func (c *Client) Logout(paths ...string) *http.Handler {
	return &http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectPath := RedirectPath
		if len(path) > 0 && path[0] != "" {
			redirectPath = path[0]
		}

		c.session = nil
		http.SetCookie(w, &http.Cookie{
			Name:     "Authorization",
			Value:    "",
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			Expires:  time.Unix(0, 0),
		})

		http.Redirect(w, r, redirectPath, 302)
	})
}

func (c *Client) XSRF(path ...string) string {
	p := ""
	if len(path) > 0 {
		p = path[0]
	}
	return xsrftoken.Generate(c.xsrfKey, "", p)
}

func (c *Client) CheckXSRF(handler *http.Handler, path ...string) *http.Handler {
	return &http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := ""
		if len(path) > 0 {
			p = path[0]
		}

		if !xsrftoken.Valid(r.PostFormValue("token"), c.xsrfKey, "", p) {
			httpError(w, 401, errors.New("invalid XSRF")
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (c *Client) EnsureAuth(handler *http.Handler) *http.Handler {
	return &http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.IsAuth() {
			httpError(w, 401)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (c *Client) IsAuth(r *http.Request) bool {
	if c.session == nil {
		return false
	}
	if c.session.expires.Before(time.Now()) {
		return false
	}
	// Useful for debugging with curl - this is *not* a valid digest auth header.
	if r.Header.Get("Authorization") == fmt.Sprintf("Hash %s", c.hash) {
	  return true
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		value := make(map[string]string)
		if err = c.cookie.Decode(cookieName, cookie.Value, &value); err == nil {
			return value["Authorization"] == c.session.id
		}
	}
	return false
}

func (c *Client) newCookie() (*http.Cookie, error) {
	s := securecookie.New(c.hashKey, c.blockKey)
	err := s.Encode("Authorization", c.session.id)
	if err != nil {
		return nil, err
	}

	c.cookie = s
	return &http.Cookie{
		Name:     "Authorization",
		Value:    encoded,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Expires:  c.session.expires,
	}, nil
}

func generateKey() string {
	return securecookie.GenerateRandomKey(32)
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil
}

func httpError(w http.ResponseWriter, code int, err...error) {
	msg := http.StatusText(code)
	if len(err) > 0 {
		msg = fmt.Sprintf("%s: %s", msg, err[0].Error())
	}
	http.Error(w, msg, code)
}

func compileTemplates(filenames ...string) (*template.Template, error) {
	m := minify.New()
	m.AddFunc("text/html", html.Minify)

	var tmpl *template.Template
	for _, filename := range filenames {
		name := filepath.Base(filename)
		if tmpl == nil {
			tmpl = template.New(name)
		} else {
			tmpl = tmpl.New(name)
		}

		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		mb, err := m.Bytes("text/html", b)
		if err != nil {
			return nil, err
		}
		tmpl.Parse(string(mb))
	}
	return tmpl, nil
}
