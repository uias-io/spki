package cacert

import (
	"crypto"
	"crypto/x509"
	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/uuid4"
)

// ---------- 签发末端证书 ----------

func IssueEndEntitySvc(dao *models.DB, issuerID string, cfg *CertConfig) (string, error) {
	// 1. 配置校验 → 参数校验失败
	if err := validateConfig(cfg); err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestParamsError, "invalid config", err)
	}

	// 2. 查 issuer 出错 → 内部错
	issuer, err := dao.GetCertificateByCertID(issuerID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer failed", err)
	}
	// 3. issuer 不存在 → 签发者不存在
	if issuer == nil {
		return "", ErrNotFound(answer.EcodeIssuer404, "issuer not found", nil)
	}
	// 4. issuer 不是 CA → 非 CA 证书
	if issuer.Genre != GenreRoot && issuer.Genre != GenreInter {
		return "", ErrBadRequest(answer.EcodeNonCACertificate, "issuer must be a CA certificate", nil)
	}

	// 5. 查 issuer 版本出错 → 内部错
	issuerVer, err := dao.GetLatestVersion(issuerID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer version failed", err)
	}
	// 6. 版本不存在 → 版本不存在
	if issuerVer == nil {
		return "", ErrNotFound(answer.EcodeVersion404, "issuer version not found", nil)
	}
	// 7. issuer 无私钥 → CA 无法签发
	if issuerVer.KeyID == nil {
		return "", ErrBadRequest(answer.EcodeCACannotSign, "issuer CA has no private key, cannot sign", nil)
	}

	// 8. 查 issuer key 出错 → 内部错
	issuerKey, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer key failed", err)
	}
	// 9. key 不存在 → 私钥不存在
	if issuerKey == nil {
		return "", ErrNotFound(answer.EcodePrivateKey404, "issuer key not found", nil)
	}
	// 10. 解析 issuer 证书失败 → 内部错
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse issuer cert failed", err)
	}
	// 11. 解密 issuer key 失败 → 内部错
	issuerSigner, err := decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "decrypt issuer key failed", err)
	}

	var key crypto.Signer
	var encKey string
	var encPassphrase string
	var keyFP string
	var keyIDPtr *string

	// 12. 非 CSR 模式才生成密钥
	if cfg.CSRPem == "" {
		key, err = createKey(cfg.Key.Algo, cfg.Key.Size)
		if err != nil {
			return "", ErrInternal(answer.EcodeError, "create key failed", err)
		}
		encKey, encPassphrase, err = encryptPrivateKey(key)
		if err != nil {
			return "", ErrInternal(answer.EcodeError, "encrypt private key failed", err)
		}
		keyFP, err = calcPubKeyFingerprint(key)
		if err != nil {
			return "", ErrInternal(answer.EcodeError, "calc key fingerprint failed", err)
		}
		keyID := uuid4.Uuid4Str()
		keyIDPtr = &keyID
	}

	// 13. 签发失败 → 请求/参数问题（CSR/PEM/算法等用户输入）
	der, err := signCert(key, issuerCert, issuerSigner, cfg, false)
	if err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestError, "sign end entity failed", err)
	}
	// 14. 解析新证书失败 → 内部错
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse cert failed", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certFP := calcCertFingerprint(cert)

	certID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	hasKey := int8(0)
	if cfg.CSRPem == "" {
		hasKey = 1
	}
	cfgJSON, err := marshalConfig(cfg)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "marshal config failed", err)
	}

	certRec := models.Certificate{
		CertID:   certID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: &issuerID,
		Pathlev:  PathLevLeaf,
		Genre:    GenreLeaf,
		HasKey:   hasKey,
		CertReq:  strPtrIf(cfg.CSRPem),
		IssueCfg: cfgJSON,
	}

	var keyRec *models.PrivateKey
	if cfg.CSRPem == "" {
		keyRec = &models.PrivateKey{
			KeyID:       *keyIDPtr,
			PrivateKey:  encKey,
			Passphrase:  encPassphrase,
			Fingerprint: &keyFP,
			CreateTime:  now,
		}
	}

	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          keyIDPtr,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	// 15. 存库失败 → 内部错
	if err := dao.SaveCertBundle(certRec, keyRec, version); err != nil {
		return "", ErrInternal(answer.EcodeError, "save cert bundle failed", err)
	}
	return certID, nil
}
