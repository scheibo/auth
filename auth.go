package auth

import (
	"net/http"

	"golang.org/x/net/xsrftoken"
	"golang.org/x/crypto/bcrypt"
)

// TODO must use SSL!!!!

const DefaultLoginPath = "/login"
const DefaultLogoutPath = "/logout"
const DefaultSessionPath = "/login"
const DefaultRedirectPath = "/"

type Client struct {
	hash string

	xsrfKey string
	hashKey string
	blockKey string

	loginPath string
	logoutPath string
	sessionPath string
	redirectPath string

	// TODO
	// includes session store? - needs stte to know whether loged in or not?

	// options: use ENCRYPTED cookie sotre
	// allow header for Digest


	// OPTION: 1) basic hashed password with xsrf
	//         2) "Authorization: Hash <hash>" header?
	//         3) Allow certificates (or ONLY allow certificates = need to auth only certain functions)


	// TODO xsrf token timeout!
}

// key = 32 bits
func New(options ...func(*Client)) (*Client, error) {
	c := &Client{
		xsrfKey: generateKey(),
		hashfKey: generateKey(),
		blockKey: generateKey(),

		loginPath: DefaultLoginPath,
		logoutPath: DefaultLogoutPath,
		sessionPath: DefaultSessionPath,
		redirectPath: DefaultRedirectPath,
	}
	for _, option := range options {
		err := option(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func LoginPath(path string) func(*Client) error {
	return func(*Client) error {
		c.loginPath = path
	}
}

func LogoutPath(path string) func(*Client) error {
	return func(*Client) error {
		c.logoutPath = path
	}
}

func SessionPath(path string) func(*Client) error {
	return func(*Client) error {
		c.sessionPath = path
	}
}

func RedirectPath(path string) func(*Client) error {
	return func(*Client) error {
		c.redirectPath = path
	}
}

func (c *Client) LoginPage() error {
// returns form to be rendered at LoginPath
// TODO provide option for just getting secret for xsrf and allowing site to hsot own login


// 1) generate XSRF token, include in page
// 2) include path to POST to
// 3) render page
}

func (c *Client) Login(w http.ResponseWriter, r *http.Request) {
	if !isHTTPS(req) {
		return errors.New("login request must be over HTTPS")
	}
	if r.Method != "POST" {
		return errors.New("login request must use POST")
	}

	r.ParseForm()
	var password, token = r.Form["password"], r.Form["token"]
	if !xsrftoken.Valid(token, c.key, "", "") {
		httpError(w, 401)
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		httpError(w, 401)
		return
	}
// TODO set cookie!
	http.Redirect(w, r, c.RedirectPath, 302)
}

func (c *Client) Logout(w http.ResponseWriter, r *http.Request) {
	// TODO clear cookie
	http.Redirect(w, r, c.RedirectPath, 302)
}

func (c *Client) Verify(handler *http.Handler) *http.Handler {
	// TODO optionall around a path?
	return c.EnsureAuth(c.protectXSRF(handler)
}

func (c *Client) XSRF(path ...string) string {
	p := ""
	if len(path) > 0 {
		p = path[0]
	}
	return xsrftoken.Generate(c.key, "", p)
}

func (c *Client) CheckXSRF(w http.ResponseWriter, r *http.Request, path ...string) {
	p := ""
	if len(path) > 0 {
		p = path[0]
	}

	r.ParseForm()
	token := r.Form["token"]
	if !xsrftoken.Valid(r.Form["token"], c.key, "", p) {
		httpError(w, 403)
		return
	}
}

func (c *Client) IsAuth(req *http.Request) bool {
	// TODO check cookie
}

func (c *Client) EnsureAuth(handler *http.Handler) *http.Handler {
	return &http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.IsAuth() {
			httpError(w, 403)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

func (c *Client) Hash(password string) string, error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (c *Client) generateKey() string {
	return securecookie.GenerateRandomKey(32)
}

func (c *Client) newCookie() {
	var hashKey = []byte(c.hashKey)
	var blockKey = []byte(securecookie.GenerateRandomKey(32))
}

func isHTTPS(req *http.Request) bool {
	return req.TLS != nil
}

func httpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}



