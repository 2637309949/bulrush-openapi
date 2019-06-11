# bulrush-openapi
    RSA 算法 RSA PKCS#1, SHA256

```go
// Init OpenApi
// OpenAPI Plugin init
var OpenAPI = &openapi.OpenAPI{
    URLPrefix: "/gateway",
    // Auth AppID
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
}
// Regist a handler
// openapi is a inject from bulrush, see my bulrush-template for more detail info
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