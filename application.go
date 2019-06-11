/**
 * @author [Double]
 * @email [2637309949@qq.com.com]
 * @create date 2019-01-12 22:46:31
 * @modify date 2019-01-12 22:46:31
 * @desc [bulrush openapi]
 */

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
	// OpenAPI for third party dev
	OpenAPI struct {
		bulrush.PNBase
		URLPrefix string
		apis      []Handler
		Auth      func(appid string) (*AppInfo, error)
	}
	// AppInfo app key secret
	AppInfo struct {
		AppID     string
		PublicKey string
		// JUST FOR TEST
		PrivateKey string
	}
	// CRP Common request parameter
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
	// CRPRet return after voke func
	CRPRet struct {
		RetURL string
		Noti   *Noti
		Body   interface{}
	}
	// Noti noti body
	Noti struct {
		URL  string
		Mess map[string]interface{}
	}
	// Voke func
	Voke func(*AppInfo, *CRP) (*CRPRet, error)
	// Handler api handler
	Handler struct {
		Name    string
		Version string
		Voke    Voke
	}
)

// Plugin for Recovery
// Request Params
// app_id         String           是     分配给开发者的应用ID
// method         String           是     接口名称 xxx.xxx.xx.xx
// format         String           否     仅支持JSON JSON
// return_url     String           否     HTTP/HTTPS开头字符串 https://xx.xx.com/xx
// charset        String           是     请求使用的编码格式，如utf 8,gbk,gb2312等 utf 8
// sign_type      String           是     生成签名字符串所使用的签名算法类型，RSA2和RSA，目前RSA
// sign           String           是     请求参数的签名串
// timestamp      String           是     发送请求的时间，格式"yyyy MM dd HH:mm:ss" 2014 07 24 03:07:50
// version        String           是     调用的接口版本，固定为：1.0 1.0
// notify_url     String           否     服务器主动通知商户服务器里指定的页面http/https路径。
// app_auth_token String           否     应用授权
// biz_content    String           是     请求参数的集合，最大长度不限，除公共参数外所有请求参数都必须放在这个参数中传递
func (openapi *OpenAPI) Plugin() bulrush.PNRet {
	return func(cfg *bulrush.Config, router *gin.RouterGroup) *OpenAPI {
		router.GET(openapi.URLPrefix, openapi.requestHandle)
		router.POST(openapi.URLPrefix, openapi.requestHandle)
		return openapi
	}
}

// RegistHandler for register open handler
func (openapi *OpenAPI) RegistHandler(h Handler) (bool, error) {
	existedHandler := funk.Find(openapi.apis, func(handler Handler) bool {
		return (handler.Name == h.Name) && (handler.Version == h.Version)
	})
	if existedHandler != nil {
		rushLogger.Warn("Handler has existedd %s", existedHandler)
		return false, fmt.Errorf("Handler has existedd %s", existedHandler)
	}
	openapi.apis = append(openapi.apis, h)
	return true, nil
}

func getForm(c *gin.Context) (*CRP, error) {
	puData := &CRP{}
	if c.Request.Method != "POST" {
		if err := c.ShouldBindQuery(puData); err != nil {
			return nil, err
		}
	} else {
		if err := c.ShouldBind(puData); err != nil {
			return nil, err
		}
	}
	return puData, nil
}

// handle http request
func (openapi *OpenAPI) requestHandle(c *gin.Context) {
	puData, err := getForm(c)
	if err != nil {
		rushLogger.Warn("getForm error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	appKeySecret, err := openapi.auth(puData, c)
	if err != nil {
		rushLogger.Warn("auth error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	voke, err := openapi.findVoke(puData.Method, puData.Version)
	if err != nil {
		rushLogger.Warn("findVoke error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	ret, err := voke(appKeySecret, puData)
	if err != nil {
		rushLogger.Warn("voke error %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		c.Abort()
		return
	}
	if ret.RetURL != "" {
		c.Redirect(http.StatusMovedPermanently, ret.RetURL)
		c.Abort()
		return
	}
	if ret.Noti != nil {
	}
	c.JSON(http.StatusOK, ret.Body)
}

func (openapi *OpenAPI) findVoke(method string, version string) (Voke, error) {
	h := funk.Find(openapi.apis, func(handler Handler) bool {
		return (handler.Name == method) && (handler.Version == version)
	})
	if h == nil {
		rushLogger.Warn("Not existedd %s %s", method, version)
		return nil, fmt.Errorf("Not existedd %s %s", method, version)
	}
	v := h.(Handler).Voke
	return v, nil
}

func (openapi *OpenAPI) auth(puData *CRP, c *gin.Context) (*AppInfo, error) {
	if appKeySecret, err := openapi.Auth(puData.AppID); err == nil {
		if err := rsaVerify(puData, appKeySecret); err != nil {
			rushLogger.Warn("rsaVerify error %s", err.Error())
			return nil, err
		}
		return appKeySecret, nil
	}
	return nil, errors.New("app not found")
}

func rsaVerify(puData *CRP, appKeySecret *AppInfo) error {
	sign := puData.Sign
	signString := map2SignString(puData)
	if pubkey, err := pubKeyFromByte([]byte(appKeySecret.PublicKey)); err == nil {
		if err := rsaVerifyPKCS1v15(pubkey, []byte(signString), sign); err != nil {
			rushLogger.Warn("rsaVerifyPKCS1v15 error %s", err.Error())
			return errors.New("sign not match")
		}
		return nil
	}
	rushLogger.Warn("pubKeyFromByte error")
	return errors.New("read application public key error")
}
