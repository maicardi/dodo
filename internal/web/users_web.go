package web

import (
 "crypto/rand"
 "encoding/base64"
 "net/http"
 "net/mail"
 "net/url"
 "strings"

 "github.com/mtzanidakis/dodo/internal/auth"
 "github.com/mtzanidakis/dodo/internal/i18n"
 "github.com/mtzanidakis/dodo/internal/models"
)

func (h *Handler) handleRegisterPage(w http.ResponseWriter,r *http.Request) {
 if !h.deps.Mail.Ready() { http.NotFound(w,r);return }
 h.render(w,"auth/register.html",pageData{Title:i18n.T("register.title","en"),Lang:"en",
   CSRF:auth.IssueCSRF(w),ColorScheme:"light dark",RegistrationEnabled:true})
}

func (h *Handler) handleRegisterPost(w http.ResponseWriter,r *http.Request) {
 if !h.deps.Mail.Ready() { http.NotFound(w,r);return }
 email:=strings.ToLower(strings.TrimSpace(r.FormValue("email")))
 password:=r.FormValue("password")
 addr,err:=mail.ParseAddress(email)
 if err!=nil || addr.Address!=email || len(password)<8 || len(email)>254 {
    http.Redirect(w,r,"/register?invalid=1",http.StatusSeeOther);return
 }
 if !h.deps.LoginRL.Allow(r,email) {
    http.Error(w,"Too many requests",http.StatusTooManyRequests);return
 }
 h.deps.LoginRL.RecordFailure(r,email)
 hash,err:=auth.HashPassword(password)
 if err!=nil { http.Error(w,"Service error",http.StatusInternalServerError);return }
 raw:=make([]byte,32)
 if _,err=rand.Read(raw);err!=nil { http.Error(w,"Service error",http.StatusInternalServerError);return }
 token:=base64.RawURLEncoding.EncodeToString(raw)
 u:=&models.User{Email:email,PasswordHash:hash,DisplayName:strings.TrimSpace(r.FormValue("display_name"))}
 err=h.deps.Store.Users.CreatePending(r.Context(),u,auth.HashToken(token))
 if err==nil {
    if err=h.deps.Mail.SendVerification(r.Context(),email,token);err!=nil {
       http.Error(w,"Email delivery failed; contact the administrator",http.StatusBadGateway);return
    }
 }
 http.Redirect(w,r,"/login?registration=sent",http.StatusSeeOther)
}

func (h *Handler) handleVerifyEmail(w http.ResponseWriter,r *http.Request) {
 token:=r.URL.Query().Get("token")
 if len(token)<30 || len(token)>256 { http.Error(w,"Invalid verification link",http.StatusBadRequest);return }
 if err:=h.deps.Store.Users.VerifyEmail(r.Context(),auth.HashToken(token));err!=nil {
   http.Error(w,"Expired or already used verification link",http.StatusBadRequest);return
 }
 http.Redirect(w,r,"/login?registration=verified",http.StatusSeeOther)
}

func (h *Handler) handleAdmin(w http.ResponseWriter,r *http.Request) {
 u:=auth.UserFromContext(r.Context())
 if !u.IsAdmin() { http.Error(w,"Forbidden",http.StatusForbidden);return }
 users,err:=h.deps.Store.Users.List(r.Context())
 if err!=nil { http.Error(w,"Service error",http.StatusInternalServerError);return }
 pd:=h.base(w,r,u,i18n.T("admin.title",string(u.Locale)),"admin")
 pd.Users=users
 pd.Flash=r.URL.Query().Get("ok")
 pd.Error=r.URL.Query().Get("err")
 h.render(w,"admin/index.html",pd)
}

func (h *Handler) adminChange(w http.ResponseWriter,r *http.Request, fn func()error) {
 u:=auth.UserFromContext(r.Context())
 if !u.IsAdmin() { http.Error(w,"Forbidden",http.StatusForbidden);return }
 if err:=fn();err!=nil {
   http.Redirect(w,r,"/admin?err="+url.QueryEscape(i18n.T("admin.failed",string(u.Locale))),http.StatusSeeOther);return
 }
 http.Redirect(w,r,"/admin?ok="+url.QueryEscape(i18n.T("admin.saved",string(u.Locale))),http.StatusSeeOther)
}

func (h *Handler) handleAdminCreate(w http.ResponseWriter,r *http.Request) {
 h.adminChange(w,r,func() error {
   email:=strings.ToLower(strings.TrimSpace(r.FormValue("email")))
   addr,err:=mail.ParseAddress(email)
   if err!=nil || addr.Address!=email || len(email)>254 || len(r.FormValue("password"))<8 { return models.ErrValidation }
   hash,err:=auth.HashPassword(r.FormValue("password"))
   if err!=nil { return err }
   return h.deps.Store.Users.Create(r.Context(),&models.User{Email:email,PasswordHash:hash,
      DisplayName:strings.TrimSpace(r.FormValue("display_name"))})
 })
}

func (h *Handler) handleAdminRole(w http.ResponseWriter,r *http.Request) {
 h.adminChange(w,r,func()error{return h.deps.Store.Users.SetRole(r.Context(),r.PathValue("id"),r.FormValue("role"))})
}
func (h *Handler) handleAdminStatus(w http.ResponseWriter,r *http.Request) {
 h.adminChange(w,r,func()error{return h.deps.Store.Users.SetDisabled(r.Context(),r.PathValue("id"),r.FormValue("disabled")=="true")})
}
func (h *Handler) handleAdminDelete(w http.ResponseWriter,r *http.Request) {
 h.adminChange(w,r,func()error{return h.deps.Store.Users.DeletePermanently(r.Context(),r.PathValue("id"))})
}
