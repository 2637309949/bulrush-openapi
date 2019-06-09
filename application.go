/**
 * @author [Double]
 * @email [2637309949@qq.com.com]
 * @create date 2019-01-12 22:46:31
 * @modify date 2019-01-12 22:46:31
 * @desc [bulrush openapi]
 */

package openapi

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/2637309949/bulrush"
	"github.com/gin-gonic/gin"
	"github.com/thoas/go-funk"
)

type (
	// OpenAPI for third party dev
	OpenAPI struct {
		bulrush.PNBase
		URLPrefix string
		apis      []Handler
		Auth      func(appid string) (*AppKeySecret, error)
	}
	// AppKeySecret app key secret
	AppKeySecret struct {
		AppKey    string
		AppSecret string
	}
	// CRP Common request parameter
	CRP struct {
		AppID        string `form:"app_id" json:"app_id" xml:"app_id" binding:"required"`
		Method       string `form:"method" json:"method" xml:"method" binding:"required"`
		Format       string `form:"format" json:"format" xml:"format"`
		ReturnURL    string `form:"return_url" json:"return_url" xml:"return_url"`
		Charset      string `form:"charset" json:"charset" xml:"charset" binding:"required"`
		SignType     string `form:"sign_type" json:"sign_type" xml:"sign_type" binding:"required"`
		Sign         string `form:"sign" json:"sign" xml:"sign" binding:"required"`
		TimeStamp    string `form:"timestamp" json:"timestamp" xml:"timestamp" binding:"required"`
		Version      string `form:"version" json:"version" xml:"version" binding:"required"`
		NotifyURL    string `form:"notify_url" json:"notify_url" xml:"notify_url"`
		AppAuthToken string `form:"app_auth_token" json:"app_auth_token" xml:"app_auth_token"`
		BizContent   string `form:"biz_content" json:"biz_content" xml:"biz_content" binding:"required"`
	}
	// CRPRet return after voke func
	CRPRet struct {
		ReturnURL string
		NotiMess  *NotiMess
		Body      interface{}
	}
	// NotiMess noti body
	NotiMess struct {
		URL  string
		Mess map[string]interface{}
	}
	// Voke func
	Voke func(*AppKeySecret, *CRP) (*CRPRet, error)

	// Handler api handler
	Handler struct {
		Name    string
		Version string
		Voke    Voke
	}
)

// Plugin for Recovery
// Request Params
// ihgjb 1111  sefld134r34eruwiru2323rjisfjsd
// return_url     String           否     HTTP/HTTPS开头字符串 https://xx.xx.com/xx
// charset        String           是     请求使用的编码格式，如utf 8,gbk,gb2312等 utf 8
// sign_type      String           是     生成签名字符串所使用的签名算法类型，RSA2和RSA，推荐使用RSA2
// sign           String           是     请求参数的签名串，详见签名 详见示例
// timestamp      String           是     发送请求的时间，格式"yyyy MM dd HH:mm:ss" 2014 07 24 03:07:50
// version        String           是     调用的接口版本，固定为：1.0 1.0
// notify_url     String           否     服务器主动通知商户服务器里指定的页面http/https路径。
// app_auth_token String           否     应用授权
// biz_content    String           是     请求参数的集合，最大长度不限，除公共参数外所有请求参数都必须放在这个参数中传递
func (openapi *OpenAPI) Plugin() bulrush.PNRet {
	return func(cfg *bulrush.Config, router *gin.RouterGroup) *OpenAPI {
		router.POST(openapi.URLPrefix, openapi.reqHandle)
		return openapi
	}
}

// RegistHandler for register open handler
func (openapi *OpenAPI) RegistHandler(h Handler) (bool, error) {
	existedHandler := funk.Find(openapi.apis, func(handler Handler) bool {
		return (handler.Name == h.Name) && (handler.Version == h.Version)
	})
	if existedHandler != nil {
		return false, fmt.Errorf("Handler has existedd %s", existedHandler)
	}
	openapi.apis = append(openapi.apis, h)
	return true, nil
}

// handle http request
func (openapi *OpenAPI) reqHandle(c *gin.Context) {
	// params check
	var puData CRP
	if err := c.ShouldBindQuery(&puData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	// auth check
	appKeySecret, err := openapi.authenticate(&puData, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		c.Abort()
		return
	}
	// find openapi
	voke, err := openapi.findVoke(puData.Method, puData.Version)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	// voke openapi
	ret, err := voke(appKeySecret, &puData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}

	if ret.ReturnURL != "" {
		c.Redirect(http.StatusMovedPermanently, "/auth/login")
		c.Abort()
		return
	}
	if ret.NotiMess != nil {
	}
	c.JSON(http.StatusOK, ret.Body)
}

func (openapi *OpenAPI) findVoke(method string, version string) (Voke, error) {
	return nil, nil
}

func (openapi *OpenAPI) authenticate(puData *CRP, c *gin.Context) (*AppKeySecret, error) {
	var puJSON map[string]interface{}
	var puKeys = make([]string, 0, len(puJSON))
	c.BindJSON(&puJSON)

	// check appid
	appKeySecret, err := openapi.Auth(puData.AppID)
	if err != nil {
		return nil, err
	}

	// check rsa
	for k := range puJSON {
		puKeys = append(puKeys, k)
	}
	sort.Strings(puKeys)
	return appKeySecret, nil
}
