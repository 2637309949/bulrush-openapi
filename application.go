// Copyright (c) 2018-2020 Double.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package openapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/2637309949/bulrush"
	"github.com/gin-gonic/gin"
	"github.com/thoas/go-funk"
)

type (
	// OpenAPI defines third party dev
	OpenAPI struct {
		bulrush.PNBase
		URLPrefix string
		apis      []Handler
		Auth      func(appid string) (*AppInfo, error)
	}
	// AppInfo defines app key secret
	AppInfo struct {
		AppID     string
		PublicKey string
		// JUST FOR TEST
		PrivateKey string
	}
	// CRP defines Common request parameter
	CRP struct {
		AppID        string `form:"app_id" json:"app_id" xml:"app_id" binding:"required"`
		Method       string `form:"method" json:"method" xml:"method" binding:"required"`
		Format       string `form:"format" json:"format" xml:"format"`
		RetURL       string `form:"return_url" json:"return_url" xml:"return_url"`
		Charset      string `form:"charset" json:"charset" xml:"charset" binding:"required"`
		SignType     string `form:"sign_type" json:"sign_type" xml:"sign_type" binding:"required"`
		Sign         string `form:"sign" json:"sign" xml:"sign" binding:"required"`
		TimeStamp    string `form:"timestamp" json:"timestamp" xml:"timestamp" binding:"required"`
		Version      string `form:"version" json:"version" xml:"version" binding:"required"`
		NotifyURL    string `form:"notify_url" json:"notify_url" xml:"notify_url"`
		AppAuthToken string `form:"app_auth_token" json:"app_auth_token" xml:"app_auth_token"`
		BizContent   string `form:"biz_content" json:"biz_content" xml:"biz_content" binding:"required"`
	}
	// CRPRet defines return after voke func
	CRPRet struct {
		RetURL string
		Noti   *Noti
		Body   interface{}
	}
	// Noti defines noti body
	Noti struct {
		URL  string
		News map[string]interface{}
	}
	// Voke defines handle call
	Voke func(*AppInfo, *CRP) (*CRPRet, error)
	// Handler api handler
	Handler struct {
		Name    string
		Version string
		Voke    Voke
	}
)

// Plugin for OpenAPI
func (api *OpenAPI) Plugin() bulrush.PNRet {
	return func(cfg *bulrush.Config, router *gin.RouterGroup) *OpenAPI {
		funk.ForEach([]func(string, ...gin.HandlerFunc) gin.IRoutes{router.GET, router.POST}, func(httpMethod func(string, ...gin.HandlerFunc) gin.IRoutes) {
			httpMethod(api.URLPrefix, api.requestHandle)
		})
		return api
	}
}

// RegistHandler defines for register open handler
func (api *OpenAPI) RegistHandler(h Handler) (bool, error) {
	if existedHandler := funk.Find(api.apis, func(handler Handler) bool {
		return (handler.Name == h.Name) && (handler.Version == h.Version)
	}); existedHandler != nil {
		rushLogger.Warn("handler has existedd %s", existedHandler)
		return false, fmt.Errorf("handler has existedd %s", existedHandler)
	}
	api.apis = append(api.apis, h)
	return true, nil
}

// handle http request
func (api *OpenAPI) requestHandle(c *gin.Context) {
	puData, err := getForm(c)
	if err != nil {
		rushLogger.Warn("getForm error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	appKeySecret, err := api.appAuth(puData, c)
	if err != nil {
		rushLogger.Warn("appAuth error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	voke, err := api.findVoke(puData.Method, puData.Version)
	if err != nil {
		rushLogger.Warn("findVoke error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	ret, err := voke(appKeySecret, puData)
	if err != nil {
		rushLogger.Warn("voke error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	if ret.Noti != nil && ret.Noti.URL != "" {
		err := api.noti(c, ret.Noti)
		if err != nil {
			rushLogger.Error("postRequest error %s", err.Error())
		}
	}
	if ret.RetURL != "" {
		rushLogger.Info("voke retUrl %s", ret.RetURL)
		c.Redirect(http.StatusMovedPermanently, ret.RetURL)
		return
	}
	c.JSON(http.StatusOK, ret.Body)
}

// Post message twice
func (api *OpenAPI) noti(c *gin.Context, noti *Noti) error {
	_, err := postRequest(noti.URL, noti.News)
	if err != nil {
		_, err := postRequest(noti.URL, noti.News)
		return err
	}
	return nil
}

func (api *OpenAPI) findVoke(method string, version string) (Voke, error) {
	h := funk.Find(api.apis, func(handler Handler) bool {
		return (handler.Name == method) && (handler.Version == version)
	})
	if h == nil {
		rushLogger.Warn("not existedd %s %s", method, version)
		return nil, fmt.Errorf("not existedd %s %s", method, version)
	}
	v := h.(Handler).Voke
	return v, nil
}

func (api *OpenAPI) appAuth(puData *CRP, c *gin.Context) (*AppInfo, error) {
	if appKeySecret, err := api.Auth(puData.AppID); err == nil {
		if err := rsaVerify(puData, appKeySecret); err != nil {
			rushLogger.Warn("rsaVerify error %s", err.Error())
			return nil, err
		}
		return appKeySecret, nil
	}
	return nil, errors.New("app not found")
}
