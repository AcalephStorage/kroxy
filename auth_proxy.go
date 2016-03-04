package main

import (
  "errors"
  "os"
  "strings"

  "crypto/tls"
  "encoding/base64"
  "io/ioutil"
  "net/http"
  "net/http/httputil"
  "net/url"

  "github.com/Sirupsen/logrus"
  "github.com/dgrijalva/jwt-go"
)

const (
  SECRET_FILE = "/.secret/idp-secret"
)

// TODO: 
//    - add better logging and error handling
//    - house keeping

func main() {
  var server1Url *url.URL
  var err error

  if server1Url, err = url.Parse(os.Getenv("KROXY_K8S_API")); err != nil {
    logrus.Fatal("Failed to parse url: ", err)
  }

  reverseProxy := modifiedSingleHost(server1Url)
  //disable tls for now when connecting to the actul kubernetes api server
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

  server := prepareServer(reverseProxy)
  err = http.ListenAndServe(":8080", server)
  if err != nil {
    logrus.Fatal("ListenAndServe: ", err)
  }
}


func getToken() string {
  token, _ := ioutil.ReadFile(os.Getenv("KROXY_TOKEN_FILE"))
  return string(token)
}

func getSecret() string {
  secret, _ := ioutil.ReadFile(SECRET_FILE)
  return string(secret)
}


// copied from net/http/httputil.something
func modifiedSingleHost(target *url.URL) *httputil.ReverseProxy {
  targetQuery := target.RawQuery
  director := func(req *http.Request) {
      req.URL.Scheme = target.Scheme
      req.URL.Host = target.Host
      req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
      req.Header.Set("Authorization", "Bearer " + getToken())
      if targetQuery == "" || req.URL.RawQuery == "" {
        req.URL.RawQuery = targetQuery + req.URL.RawQuery
      } else {
        req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
      }
  }
  return &httputil.ReverseProxy{Director: director}
}


// setup cors and validate id_token
func prepareServer(handler http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      w.Header().Set("Access-Control-Allow-Origin", "*")
      w.Header().Set("Access-Control-Allow-Headers", "authorization")
      w.Header().Set("Access-Control-Allow-Methods", "*")
      if r.Method == "OPTIONS" {
        w.WriteHeader(http.StatusOK)
      } else {
        err := validateToken(r)
        if err != nil {
          logrus.Info(err)
          w.WriteHeader(http.StatusUnauthorized)
        } else {
          handler.ServeHTTP(w, r)
        }
      }
  })
}


func validateToken(r *http.Request) error {
  var id_token string
  if auth := r.Header.Get("Authorization"); auth != "" {
    if len(auth) > 6 && strings.ToUpper(auth[0:7]) == "BEARER " {
      id_token = strings.TrimSpace(auth[7:])
    }
  } else {
    return errors.New("Missing Authorization Header.")
  }

  decoded_secret, err := base64.URLEncoding.DecodeString(getSecret())
  if err != nil {
    return err
  }

  vid_token, err := jwt.Parse(id_token, func(token *jwt.Token) (interface{}, error) { return []byte(decoded_secret), nil })
  if err == nil && vid_token.Valid{
    return nil
  }
  return errors.New("Invalid Token.")
}


// copied from net/http/httputil reverse proxy
func singleJoiningSlash(a, b string) string {
  aslash := strings.HasSuffix(a, "/")
  bslash := strings.HasPrefix(b, "/")
  switch {
    case aslash && bslash:
      return a + b[1:]
    case !aslash && !bslash:
      return a + "/" + b
  }
  return a + b
}

