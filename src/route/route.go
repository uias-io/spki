package route

import (
	"context"
	"net/http"
	"spki/src/pkg/answer"
	"spki/src/service/cacert"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
)

func Middleware(h *server.Hertz) {
	h.Use(RequestId())
	h.Use(RequestRecorder())
}

func helloWorld() func(c context.Context, ctx *app.RequestContext) {
	return func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "Hello World"})
	}
}
func r404() func(ctx context.Context, c *app.RequestContext) {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusNotFound, answer.ResBody(answer.Ecode404, "The API does not exist.", nil))
	}
}

func AppRoute(h *server.Hertz) {
	h.HEAD("")              // 健康检查
	h.GET("", helloWorld()) // 健康检查

	// OCSP
	// 签发证书时写入 OCSP URL
	// cfg.OCSPServer = []string{"http://pki.example.com/spki/ocsp"}
	//TODO OCSP需要取消鉴权
	h.POST("/spki/ocsp", apc("spki:cert:list"), cacert.OCSPResponder())
	h.GET("/spki/ocsp", cacert.OCSPResponder())

	// CA
	h.POST("/v1/spki/ca/init", apc("spki:ca:init"), cacert.InitCa())                     // 初始化根 CA
	h.POST("/v1/spki/ca/intermediate", apc("spki:ca:issue"), cacert.IssueIntermediate()) // 签发中间 CA
	h.POST("/v1/spki/ca/import", apc("spki:ca:import"), cacert.ImportCA())               // 导入CA

	// 证书操作
	h.POST("/v1/spki/cert/endentity", apc("spki:cert:issue"), cacert.IssueEndEntity())        // 签发末端证书
	h.GET("/v1/spki/cert/list", apc("spki:cert:list"), cacert.ListCert())                     // 列出证书，支持 ?genre=1&genre=2
	h.GET("/v1/spki/cert/:id", apc("spki:cert:list"), cacert.GetCert())                       // 单条详情
	h.POST("/v1/spki/cert/:id/renew", apc("spki:cert:renew"), cacert.RenewCert())             // 续签，只延长有效期
	h.POST("/v1/spki/cert/:id/revoke", apc("spki:cert:revoke"), cacert.RevokeCert())          // 吊销
	h.DELETE("/v1/spki/cert/:id", apc("spki:cert:delete"), cacert.DeleteCert())               // 删除，同时删私钥和所有版本
	h.GET("/v1/spki/cert/:id/chain", apc("spki:cert:chain"), cacert.ExportCertChain())        // 导出链，支持 ?includeRoot=false&onlyRoot=true
	h.GET("/v1/spki/cert/:id/root", apc("spki:cert:root"), cacert.FindRootCA())               // 从任意证书向上找根 CA
	h.GET("/v1/spki/cert/:id/versions", apc("spki:cert:versions"), cacert.ListCertVersions()) // 列出某证书所有版本
	h.GET("/v1/spki/cert/:id/bundle", apc("spki:cert:bundle"), cacert.ExportCertBundle())     // 下载证书含私钥
	h.GET("/v1/spki/cert/:id/issuecfg", apc("spki:cert:issuecfg"), cacert.GetCertConfig())    // 读取证书签发配置
	h.GET("/v1/spki/crl", apc("spki:crl:download"), cacert.DownloadCRL())                     // 下载 CRL，参数 ?issuerId=xxx

	h.NoRoute(r404())
}
