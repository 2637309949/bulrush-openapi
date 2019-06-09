/**
 * @author [Double]
 * @email [2637309949@qq.com.com]
 * @create date 2019-01-12 22:46:31
 * @modify date 2019-01-12 22:46:31
 * @desc [bulrush openapi]
 */

package openapi

import (
	"net/http"

	"github.com/2637309949/bulrush"
	"github.com/gin-gonic/gin"
)

type (
	// Openapi for third party dev
	Openapi struct {
		URLPrefix string
		bulrush.PNBase
	}
	// Params api params
	Params struct {
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
)

// Plugin for Recovery
// Request Params
// app_id         String           是     分配给开发者的应用ID 2014072300007148
// method         String           是     接口名称 xxx.xxx.xx.xx
// format         String           否     仅支持JSON JSON
// return_url     String           否     HTTP/HTTPS开头字符串 https://xx.xx.com/xx
// charset        String           是     请求使用的编码格式，如utf 8,gbk,gb2312等 utf 8
// sign_type      String           是     生成签名字符串所使用的签名算法类型，RSA2和RSA，推荐使用RSA2
// sign           String           是     请求参数的签名串，详见签名 详见示例
// timestamp      String           是     发送请求的时间，格式"yyyy MM dd HH:mm:ss" 2014 07 24 03:07:50
// version        String           是     调用的接口版本，固定为：1.0 1.0
// notify_url     String           否     服务器主动通知商户服务器里指定的页面http/https路径。
// app_auth_token String           否     应用授权
// biz_content    String           是     请求参数的集合，最大长度不限，除公共参数外所有请求参数都必须放在这个参数中传递
func (openapi *Openapi) Plugin() bulrush.PNRet {
	return func(cfg *bulrush.Config, router *gin.RouterGroup) {
		router.GET(openapi.URLPrefix, func(c *gin.Context) {
			var puData Params
			if error := c.ShouldBindQuery(&puData); error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": error.Error()})
				return
			}
			c.JSON(http.StatusOK, puData)
		})
		router.POST(openapi.URLPrefix, func(c *gin.Context) {
			var puData Params
			if error := c.ShouldBind(&puData); error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": error.Error()})
				return
			}
			c.JSON(http.StatusOK, puData)
		})
	}
}
