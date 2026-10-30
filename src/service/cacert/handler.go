package cacert

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/common"
	"spki/src/pkg/constants"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

func mustDao(c *app.RequestContext) (*models.DB, bool) {
	dao, err := models.NewDBModel(c.GetString(constants.InstanceIdKey))
	if err != nil {
		hlog.Error("NewDBModel: ", err)
		c.JSON(http.StatusUnauthorized, answer.ResBody(answer.EcodeInstance404, "instance not found", ""))
		return nil, false
	}
	return dao, true
}

// writeErr 统一把 Svc 错误映射成 HTTP 响应
func writeErr(c *app.RequestContext, err error) {
	var se *SvcError
	if errors.As(err, &se) {
		msg := se.Msg
		if se.Err != nil {
			msg = msg + ": " + se.Err.Error()
		}
		hlog.Errorf("svc error [%s]: %s", se.Ecode, msg)
		c.JSON(se.HttpCode, answer.ResBody(se.Ecode, msg, ""))
		return
	}
	hlog.Error("unclassified svc error: ", err)
	c.JSON(http.StatusInternalServerError, answer.ResBody(answer.EcodeError, err.Error(), ""))
}

// ---------- 初始化根 CA ----------

// InitCa POST /spki/ca/init
func InitCa() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var cfg CertConfig
		if err := c.BindJSON(&cfg); err != nil {
			hlog.Error("InitCa bind: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, "请求体错误: "+err.Error(), ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		certID, err := InitRootCA(dao, &cfg)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody(answer.EcodeOK, "", map[string]any{"certId": certID}))
	}
}

// ---------- 签发中间 CA ----------

// IssueIntermediate POST /spki/ca/intermediate
func IssueIntermediate() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			CertConfig
			Issuer struct {
				ID string `json:"id"`
			} `json:"issuer"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, err.Error(), ""))
			return
		}
		if req.Issuer.ID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "issuer.id is required", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		certID, err := IssueIntermediateSvc(dao, req.Issuer.ID, &req.CertConfig)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody(answer.EcodeOK, "", map[string]any{"certId": certID}))
	}
}

// ---------- 签发末端证书 ----------

// IssueEndEntity POST /spki/cert/endentity
func IssueEndEntity() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			CertConfig
			Issuer struct {
				ID string `json:"id"`
			} `json:"issuer"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, err.Error(), ""))
			return
		}
		if req.Issuer.ID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "issuer.id is required", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		certID, err := IssueEndEntitySvc(dao, req.Issuer.ID, &req.CertConfig)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody(answer.EcodeOK, "", map[string]any{"certId": certID}))
	}
}

// ---------- 吊销 ----------

// RevokeCert POST /spki/cert/:id/revoke
// 请求体：{"reason": "keyCompromise"}，reason 可选，不传默认 unspecified
func RevokeCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")

		var req struct {
			Reason string `json:"reason"` // 语义化 key，如 "keyCompromise"
		}
		// Body 可为空，BindJSON 失败也允许（走默认 unspecified）
		_ = c.BindJSON(&req)

		reason := models.ReasonUnspecified
		if req.Reason != "" {
			code, ok := ParseRevocationReason(req.Reason)
			if !ok {
				c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRevocationReason, "invalid revocation reason: "+req.Reason, ""))
				return
			}
			reason = code
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}
		if err := RevokeCertSvc(dao, certID, reason); err != nil {
			writeErr(c, err)
			return
		}

		// 回显：同时给出 key 和数字码，方便前端和机器各自取用
		reasonName := RevocationReasonName[reason]
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", map[string]any{
			"cert": map[string]string{
				"id": certID,
			},
			"certId": certID,
			"status": "R",
			"reason": reasonName,
			"code":   reason,
		}))
	}
}

// ---------- 删除 ----------

// DeleteCert DELETE /spki/cert/:id
func DeleteCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		if err := DeleteCertSvc(dao, certID); err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", map[string]any{"certId": certID, "deleted": true}))
	}
}

// ---------- 导出链 ----------

// ExportCertChain GET /spki/cert/:id/chain
// 参数：
//
//	includeRoot=true|false  链里是否包含根 CA，默认 true
//	onlyRoot=true|false     只返回根 CA 的 PEM，默认 false
//
// 用法：
//
//	/chain                    完整链（末端 + 中间 + 根）
//	/chain?includeRoot=false  不含根
//	/chain?onlyRoot=true      只返回根 CA
func ExportCertChain() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		includeRoot := c.DefaultQuery("includeRoot", "true") != "false"
		onlyRoot := c.DefaultQuery("onlyRoot", "false") == "true"

		var chain string
		var err error
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		if onlyRoot {
			chain, err = BuildRootPEM(dao, certID)
		} else {
			chain, err = BuildCertChain(dao, certID, includeRoot)
		}
		if err != nil {
			writeErr(c, err)
			return
		}
		c.Data(http.StatusOK, "application/x-pem-file", []byte(chain))
	}
}

// ---------- CRL ----------

// DownloadCRL GET /spki/crl?issuerId=xxx&validFor=1m
func DownloadCRL() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		issuerID := c.Query("issuerId")
		if issuerID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "issuerId is required", ""))
			return
		}

		// validFor 可选，默认 7d
		validFor := c.DefaultQuery("valid", "7d")

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		crl, err := BuildCRL(dao, issuerID, validFor)
		if err != nil {
			writeErr(c, err)
			return
		}

		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crl.pem"`, issuerID))
		c.Data(http.StatusOK, "application/x-pem-file", []byte(crl))
	}
}

// ---------- 续签 ----------

// RenewCert POST /spki/cert/:id/renew
func RenewCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		var req struct {
			Expiry Expiry `json:"expiry"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, "请求体错误: "+err.Error(), ""))
			return
		}
		if req.Expiry.Years == 0 && req.Expiry.Months == 0 && req.Expiry.Days == 0 {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidExpiry, "expiry is required", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}
		rev, err := RenewCertSvc(dao, certID, req.Expiry)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", map[string]any{
			"certId":   certID,
			"revision": rev,
		}))
	}
}

// ---------- 查询 ----------

// Query 查询参数
type Query struct {
	Genre  []int `query:"genre"`
	HasKey *int  `query:"hk"`
}

// ListCert GET /spki/cert?genre=1&genre=2
// 支持多个 genre：
//
//		?genre=1&genre=2  → 查根 CA + 中间 CA
//		?genre=3          → 查末端证书
//		不传              → 全部
//	    ?hk=1 → 存在私钥，可签下级证书,不传，查全部
func ListCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {

		var query Query
		if err := c.BindQuery(&query); err != nil {
			hlog.Error("ListCert bind: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "参数错误: "+err.Error(), ""))
			return
		}
		a, _ := common.FromContext(ctx)
		fmt.Println("====>", a.Account)
		// 校验 genre 范围
		for _, g := range query.Genre {
			if g < 1 || g > 3 {
				c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "genre must be 1/2/3", ""))
				return
			}
		}
		offset, limit, err := common.GetPagingQuery(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "参数错误", ""))
			return
		}

		hasKey := -1
		if query.HasKey != nil {
			if *query.HasKey != 0 && *query.HasKey != 1 {
				c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "hasKey must be 0 or 1", ""))
				return
			}
			hasKey = *query.HasKey
		}
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		count := int64(0)
		items, err := ListCertsByGenres(dao, offset, limit, &count, query.Genre, hasKey)
		if err != nil {
			writeErr(c, err)
			return
		}

		payload := map[string]any{
			"page_info": answer.SetPageInfo(offset, limit, count),
			"items":     items,
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, nil, payload))

	}
}

// GetCert GET /v1/spki/cert/:id
// 返回单条证书详情，结构复用列表项 CertListItem
func GetCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		if certID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "id is required", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		item, err := GetCertSvc(dao, certID)
		if err != nil {
			writeErr(c, err)
			return
		}

		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", item))
	}
}

// ListCertVersions GET /spki/cert/:id/versions
func ListCertVersions() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		items, err := ListCertVersionsSvc(dao, certID)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}

// FindRootCA GET /spki/cert/:id/root
// 从任意证书向上找到根 CA
func FindRootCA() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		info, err := FindRootCASvc(dao, certID)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", info))
	}
}

func ExportCertBundle() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		cert, err := dao.GetCertificateByCertID(certID)
		if err != nil {
			writeErr(c, ErrInternal(answer.EcodeError, "query cert failed", err))
			return
		}
		if cert == nil {
			c.JSON(http.StatusNotFound, answer.ResBody(answer.EcodeCertificate404, "certificate not found", ""))
			return
		}
		if cert.Genre != GenreLeaf {
			c.JSON(http.StatusForbidden, answer.ResBody(answer.EcodeCACannotBeDownloaded, "CA private key cannot be downloaded", ""))
			return
		}

		zipData, zipName, err := GetCertZip(dao, certID)
		if err != nil {
			writeErr(c, err)
			return
		}

		c.Header("Content-Disposition", "attachment; filename=\""+zipName+"\"")
		c.Data(http.StatusOK, "application/zip", zipData)
	}
}

// ---------- 导入 CA ----------

// ImportCA POST /spki/ca/import
// 只导入根 CA 或中间 CA
func ImportCA() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req ImportCAReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, "请求体错误: "+err.Error(), ""))
			return
		}
		if req.CertPem == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestParamsError, "certPem is required", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}
		resp, err := ImportCASvc(dao, &req)
		if err != nil {
			writeErr(c, err)
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody(answer.EcodeOK, "", resp))
	}
}

// OCSPResponder POST /spki/ocsp
// 接收 DER 编码的 OCSPRequest，返回 DER 编码的 OCSPResponse
func OCSPResponder() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// OCSP 请求是二进制，直接用 Body()
		reqDER := c.Request.Body()
		if len(reqDER) == 0 {
			c.JSON(http.StatusBadRequest, answer.ResBody(answer.EcodeInvalidRequestError, "empty ocsp request", ""))
			return
		}

		dao, ok := mustDao(c)
		if !ok {
			return
		}

		respDER, err := OCSPResponderSvc(dao, reqDER)
		if err != nil {
			writeErr(c, err)
			return
		}

		c.Data(http.StatusOK, "application/ocsp-response", respDER)
	}
}

// GetCertConfig GET /v1/spki/cert/:id/config
// 读取现有证书的签发配置
func GetCertConfig() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		dao, ok := mustDao(c)
		if !ok {
			return
		}
		cfg, err := GetCertConfigSvc(dao, certID)
		if err != nil {
			writeErr(c, err)
			return
		}

		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, "", map[string]any{
			"issuecfg": cfg,
		}))
	}
}
