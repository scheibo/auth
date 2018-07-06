// a1 provides simple authentication and authorization helpers for a single user
// service. Clients should use Hash to hash their password ahead of time,
// then initialize a Client with using New with the hash so that it may then be
// used to authenticate web sevices. a1 provides its own simple LoginPage which
// POSTS to /login to complete the Login flow, as well as a handler for Logout.
// a1 uses a secure cookie to store the client's login state, though it also
// supports an 'Authorization' header with the password hash for simple
// debugging purposes. a1 also provides rate limiting and XSRF functionality.
package a1

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"github.com/didip/tollbooth"
	"github.com/gorilla/securecookie"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/html"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/xsrftoken"
)

// LoginPath is the default path used for hosting both the LoginPage (GET) and
// for performing Login (POST). Alternative paths can be passed to these
// functions if desired.
const LoginPath = "/login"

// LogoutPath is the default path for logging out. An alternative path can be
// passed to Logout if desired.
const LogoutPath = "/logout"

// RedirectPath is the default path the user is redirected to after a
// successful Login or Logout. Alternatives may be used instead.
const RedirectPath = "/"

// CookieName used by a1 for authorization.
const CookieName = "Authorization"

// Client holds the state required by a1 to verify a user. A new client can be
// created using New.
type Client struct {
	hash []byte

	session *Session
	cookie  *securecookie.SecureCookie

	xsrfKey  string
	hashKey  []byte
	blockKey []byte
}

// Session holds the state for a logged in user. Sessions expire after an
// interval (default 30 days).
type Session struct {
	id      string
	expires time.Time
}

// Hash returns the hash of a password that should be passed to New and used to
// authenticate the user.
func Hash(password string) (string, error) {
	// In case the user chose a short password we SHA512 it first to make
	// sure all the passwords we bcrypt are of a decent length.
	sha := sha512.Sum512([]byte(password))
	bytes, err := bcrypt.GenerateFromPassword(sha[:64], bcrypt.DefaultCost)
	return string(bytes), err
}

// New takes a hash returned from Hash and returns a new Client which can be
// used for authenticating users.
func New(hash string) *Client {
	return &Client{
		hash:     []byte(hash),
		xsrfKey:  string(generateKey()),
		hashKey:  generateKey(),
		blockKey: generateKey(),
	}
}

// LoginPage returns a default login page that will POST its form to the
// optional path argument or LoginPath. The page can be further customized
// through the use of CustomLoginPage.
func (c *Client) LoginPage(path ...string) http.Handler {
	return c.CustomLoginPage("https://raw.githubusercontent.com/scheibo/auth/master/favicon.png", "Login")
}

// CustomLoginPage allows for tweaking the favicon and title of the page that
// LoginPage provides.
func (c *Client) CustomLoginPage(favicon, title string, path ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginPath := LoginPath
		if len(path) > 0 && path[0] != "" {
			loginPath = path[0]
		}

		t := template.Must(compileTemplates("login.html"))
		_ = t.Execute(w, struct {
			Favicon string
			Title   string
			Path    string
			Token   string
		}{
			favicon, title, loginPath, c.XSRF(loginPath),
		})
	})
}

// RateLimit restricts the qps of a wrapped handler.
func RateLimit(qps float64, handler http.Handler) http.Handler {
	return tollbooth.LimitFuncHandler(tollbooth.NewLimiter(qps, nil), handler.ServeHTTP)
}

// Login authenticates users provided the password they POST hash to the same
// hash the client was initialized with. By default, LoginPath is used for
// verifying XSRF and users are redirected to RedirectPath after successfully
// loggin in, but alternatives may be passed in through the paths parameter.
func (c *Client) Login(paths ...string) http.Handler {
	loginPath, redirectPath := LoginPath, RedirectPath
	if len(paths) >= 1 {
		if paths[0] != "" {
			loginPath = paths[0]
		}
		if len(paths) > 1 && paths[1] != "" {
			redirectPath = paths[1]
		}
	}

	// We rate limit our login attempts to prevent an attacker for repeatedly guessing passwords.
	// We also restrict the XSRF token to be scoped to the loginPath.
	return RateLimit(1, c.CheckXSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			httpError(w, 500, errors.New("login request must use POST"))
		}

		password := r.PostFormValue("password")
		sha := sha512.Sum512([]byte(password))
		err := bcrypt.CompareHashAndPassword(c.hash, sha[:64])
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
	}), loginPath))
}

// Logout logs a user out, clearing the session and then redirecting them to the
// optional path passed in or RedirectPath.
func (c *Client) Logout(path ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// XSRF returns a token (which can optionally be scoped to a specific path) to
// be used for thrwating cross-site request forgery along with CheckXSRF.
func (c *Client) XSRF(path ...string) string {
	p := ""
	if len(path) > 0 {
		p = path[0]
	}
	return xsrftoken.Generate(c.xsrfKey, "", p)
}

// CheckXSRF wraps a handler and ensures POST requests to the handler contain a
// token returned by an XSRF call (with optional path) in the body.
func (c *Client) CheckXSRF(handler http.Handler, path ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := ""
		if len(path) > 0 {
			p = path[0]
		}

		if !xsrftoken.Valid(r.PostFormValue("token"), c.xsrfKey, "", p) {
			httpError(w, 401, errors.New("invalid XSRF"))
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// EnsureAuth wraps a handler and ensures requests to it are authenticated
// before allowing it to proceed.
func (c *Client) EnsureAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.IsAuth(r) {
			httpError(w, 401)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// IsAuth checks whether a request r is authenticated by this client (i.e. the
// session is present and hasn't expired and the decoded cookie matches the
// session).
func (c *Client) IsAuth(r *http.Request) bool {
	// Useful for debugging with curl - this is *not* a valid digest auth header.
	if r.Header.Get(CookieName) == fmt.Sprintf("Hash %s", c.hash) {
		return true
	}
	if c.session == nil {
		return false
	}
	if c.session.expires.Before(time.Now()) {
		return false
	}
	if cookie, err := r.Cookie(CookieName); err == nil {
		value := make(map[string]string)
		if err = c.cookie.Decode(CookieName, cookie.Value, &value); err == nil {
			return value[CookieName] == c.session.id
		}
	}
	return false
}

func (c *Client) newCookie() (*http.Cookie, error) {
	s := securecookie.New(c.hashKey, c.blockKey)
	encoded, err := s.Encode(CookieName, c.session.id)
	if err != nil {
		return nil, err
	}

	c.cookie = s
	return &http.Cookie{
		Name:     CookieName,
		Value:    encoded,
		Secure:   true,
		HttpOnly: true,
		Path:     "/",
		Expires:  c.session.expires,
	}, nil
}

func generateKey() []byte {
	return securecookie.GenerateRandomKey(32)
}

func httpError(w http.ResponseWriter, code int, err ...error) {
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
		_, err = tmpl.Parse(string(mb))
		if err != nil {
			return nil, err
		}
	}
	return tmpl, nil
}
