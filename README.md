# bulrush-openapi
    插件涉及的算法 RSA PKCS#1, 哈希使用SHA256
## 参数
    app_id         String           是     分配给开发者的应用ID
    method         String           是     接口名称 xxx.xxx.xx.xx
    format         String           否     仅支持JSON JSON
    return_url     String           否     HTTP/HTTPS开头字符串 https://xx.xx.com/xx
    charset        String           是     请求使用的编码格式，如utf 8,gbk,gb2312等 utf 8
    sign_type      String           是     生成签名字符串所使用的签名算法类型，RSA2和RSA，目前RSA
    sign           String           是     请求参数的签名串
    timestamp      String           是     发送请求的时间，格式"yyyy MM dd HH:mm:ss" 2014 07 24 03:07:50
    version        String           是     调用的接口版本，固定为：1.0 1.0
    notify_url     String           否     服务器主动通知商户服务器里指定的页面http/https路径。
    app_auth_token String           否     应用授权
    biz_content    String           是     请求参数的集合，最大长度不限，除公共参数外所有请求参数都必须放在这个参数中传递
## Example
```shell
curl -H "Content-Type:application/json" -H "Data_Type:msg" -X POST --data  \
{
	"app_id": "xxx",
	"method": "test.hello",
	"format": "xxx",
	"return_url": "xxx",
	"charset": "xxx",
	"sign": "uj0Jm/MFqP9bz+ZBCJuTCwQp4Cmr3DJS/mAxbyIK1xS0oUmgX7OPYK4i/PSJwam \
        ZsTNAvswfRWQAFpa5550fTQZ5HNHH91Fz3cIeUOv/YWoHkku3BJbgZaSlClSBNqlhqhwm \
        ci6bJzGans2YSRP1VaNI3ZPSedDUFPYKQuyFJjQ=",
	"sign_type": "xxx",
	"timestamp": "xxx",
	"notify_url": "xxx",
	"biz_content": "xxx",
	"version": "1.0"
} \
http://127.0.0.1:8080/api/v1/gateway?accessToken=DEBUG
```

```go
// Mount Plugin
app.Use(&openapi.OpenAPI{
    URLPrefix: "/gateway",
	Auth: func(appid string) (*openapi.AppInfo, error) {
		return &openapi.AppInfo{
			AppID: "xxx",
			PublicKey: `
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDaYoospKXldKm+/fdGh8b5Jbq4
PSrIELjHR/F6+zYExr7w0XGWC6/1Nj2Da3EWYnWo+n6URMqeyCnd09SvEmavpkUW
d/4AhjZIvO42PBy9x/wFrqgU/KUqZ2r+AWFJJZgSA9IuBEqjZxsu1XTKiT7v5U7N
WlboP5QLPPffz92sUwIDAQAB
			`,
		}, nil
	},
})
// Regist a handler
app.Use(bulrush.PNQuick(func(api *openapi.OpenAPI) {
    api.RegistHandler(openapi.Handler{
        Name:    "test.hello",
        Version: "1.0",
        Voke: func(*openapi.AppInfo, *openapi.CRP) (*openapi.CRPRet, error) {
            return &openapi.CRPRet{
                Body: map[string]interface{}{
                    "a": "a",
                    "b": "b",
                },
            }, nil
        },
    })
}))
```

## RSA Generate Key
### Note
    // PKCS1 header format
    // For private key
    -----BEGIN RSA PRIVATE KEY-----
    -----END RSA PRIVATE KEY-----
    // For public key
    -----BEGIN RSA PUBLIC KEY-----
    -----END RSA PUBLIC KEY-----

    // and PKCS8 header format
    // For private key
    -----BEGIN PRIVATE KEY-----
    -----END PRIVATE KEY-----
    // For public key 
    -----BEGIN PUBLIC KEY-----
    -----END PUBLIC KEY-----

### Generate private key
```shell
openssl genrsa -out private.pem 1024
```
### Generate public key
```shell
openssl rsa -in private.pem -pubout > public.pem
```
### PKCS8 public key to PKCS1 public key format
```shell
openssl rsa -pubin -in public.pem -RSAPublicKey_out
```


## MIT License

Copyright (c) 2018-2020 Double

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.