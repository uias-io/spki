package cacert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"spki/src/models"
	"spki/src/pkg/answer"
)

// ---------- 续签 ----------

// RenewCertSvc 续签统一入口
//   - 根 CA（parent_id == NULL）→ 自签名
//   - 中间 CA / 末端证书 → 上级 CA 签
func RenewCertSvc(dao *models.DB, certID string, expiry Expiry) (int, error) {
	if expiry.Years == 0 && expiry.Months == 0 && expiry.Days == 0 {
		return 0, ErrBadRequest(answer.EcodeInvalidExpiry, "expiry is required", nil)
	}

	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cert == nil {
		return 0, ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}

	// 根 CA：自签名
	if cert.ParentID == nil {
		return renewCert(dao, certID, expiry, true, true)
	}

	// 中间 CA 或末端证书：上级签
	isCA := cert.Genre == GenreInter
	return renewCert(dao, certID, expiry, isCA, false)
}

// renewCert 续签核心
//
//	selfSign = true  → 自签名（根 CA）
//	selfSign = false → 上级签（中间 CA / 末端证书）
//	isCA     = true  → CA 证书
//	isCA     = false → 末端证书
func renewCert(dao *models.DB, certID string, expiry Expiry, isCA, selfSign bool) (int, error) {
	// 1. 查原证书
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cert == nil {
		return 0, ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}

	// 2. 查原证书最新版本
	oldVer, err := dao.GetLatestVersion(certID)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "query version failed", err)
	}
	if oldVer == nil {
		return 0, ErrNotFound(answer.EcodeVersion404, "version not found", nil)
	}
	if oldVer.KeyID == nil {
		return 0, ErrBadRequest(answer.EcodeCACannotSign, "old version has no key (CSR mode not supported)", nil)
	}

	// 3. 复用旧私钥
	oldKey, err := dao.GetPrivateKeyByKeyID(*oldVer.KeyID)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "query old key failed", err)
	}
	if oldKey == nil {
		return 0, ErrNotFound(answer.EcodePrivateKey404, "old private key not found", nil)
	}
	signer, err := decryptPrivateKey(oldKey.PrivateKey, oldKey.Passphrase)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "decrypt old key failed", err)
	}

	// 3.1 续签复用旧私钥：防历史导入的弱私钥被继续沿用
	if ec, ok := signer.(*ecdsa.PrivateKey); ok {
		if err := checkECDSAScalar(ec, minECScalarBits); err != nil {
			return 0, ErrBadRequest(answer.EcodeInvalidKeyPEM, "old private key rejected", err)
		}
	}

	// 4. 解析旧证书，还原配置
	oldCert, err := parseCertPEM(*oldVer.Cert)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "parse old cert failed", err)
	}
	cfg := buildRenewConfig(cert, oldCert, expiry, isCA)

	// 5. 取签发者
	var parentCert *x509.Certificate
	var parentSigner crypto.Signer

	if !selfSign {
		issuer, err := dao.GetCertificateByCertID(*cert.ParentID)
		if err != nil {
			return 0, ErrInternal(answer.EcodeError, "query issuer failed", err)
		}
		if issuer == nil {
			return 0, ErrNotFound(answer.EcodeIssuer404, "issuer not found", nil)
		}
		issuerVer, err := dao.GetLatestVersion(*cert.ParentID)
		if err != nil {
			return 0, ErrInternal(answer.EcodeError, "query issuer version failed", err)
		}
		if issuerVer == nil {
			return 0, ErrNotFound(answer.EcodeVersion404, "issuer version not found", nil)
		}

		if issuerVer.KeyID == nil {
			return 0, ErrBadRequest(answer.EcodeCACannotSign, "issuer CA has no private key, cannot sign", nil)
		}

		issuerKey, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
		if err != nil {
			return 0, ErrInternal(answer.EcodeError, "query issuer key failed", err)
		}
		if issuerKey == nil {
			return 0, ErrNotFound(answer.EcodePrivateKey404, "issuer key not found", nil)
		}
		parentCert, err = parseCertPEM(*issuerVer.Cert)
		if err != nil {
			return 0, ErrInternal(answer.EcodeError, "parse issuer cert failed", err)
		}
		parentSigner, err = decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
		if err != nil {
			return 0, ErrInternal(answer.EcodeError, "decrypt issuer key failed", err)
		}
	}

	// 6. 重新签一张
	der, err := signCert(signer, parentCert, parentSigner, cfg, isCA)
	if err != nil {
		return 0, ErrBadRequest(answer.EcodeInvalidRequestError, "sign renew failed", err)
	}
	newCert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "parse cert failed", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certFP := calcCertFingerprint(newCert)

	// 7. 取下一个 revision
	maxRev, err := dao.GetMaxRevision(certID)
	if err != nil {
		return 0, ErrInternal(answer.EcodeError, "get max revision failed", err)
	}
	rev := maxRev + 1

	// 8. 组装新 version
	serial := newCert.SerialNumber.Text(16)
	eff := newCert.NotBefore.UnixMilli()
	exp := newCert.NotAfter.UnixMilli()
	state := StateValid

	newVer := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          oldVer.KeyID,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	// 9. 事务写入
	if err := dao.SaveVersionWithKey(nil, newVer); err != nil {
		return 0, ErrInternal(answer.EcodeError, "save version failed", err)
	}
	return rev, nil
}

// buildRenewConfig 从旧证书还原续期配置
func buildRenewConfig(cert *models.Certificate, oldCert *x509.Certificate, expiry Expiry, isCA bool) *CertConfig {
	cfg := &CertConfig{
		Title:                cert.Title,
		Expiry:               expiry,
		SubjectKeyIdentifier: "sha256",
		Names: Names{
			CN: oldCert.Subject.CommonName,
		},
	}

	cfg.Key = inferKeySpec(oldCert)

	if len(oldCert.Subject.Organization) > 0 {
		cfg.Names.O = &oldCert.Subject.Organization[0]
	}
	if len(oldCert.Subject.OrganizationalUnit) > 0 {
		cfg.Names.OU = &oldCert.Subject.OrganizationalUnit[0]
	}
	if len(oldCert.Subject.Country) > 0 {
		cfg.Names.C = &oldCert.Subject.Country[0]
	}
	if len(oldCert.Subject.Locality) > 0 {
		cfg.Names.L = &oldCert.Subject.Locality[0]
	}
	if len(oldCert.Subject.Province) > 0 {
		cfg.Names.ST = &oldCert.Subject.Province[0]
	}

	cfg.KeyUsage = keyUsageToStrings(oldCert.KeyUsage)

	if !isCA {
		cfg.ExtKeyUsage = extKeyUsageToStrings(oldCert.ExtKeyUsage)
		cfg.AltNames.DNS = oldCert.DNSNames
		cfg.AltNames.Email = oldCert.EmailAddresses
		for _, ip := range oldCert.IPAddresses {
			cfg.AltNames.IP = append(cfg.AltNames.IP, ip.String())
		}
		for _, u := range oldCert.URIs {
			cfg.AltNames.URI = append(cfg.AltNames.URI, u.String())
		}
	}

	if isCA && oldCert.MaxPathLen >= 0 {
		pl := oldCert.MaxPathLen
		cfg.PathLen = &pl
	}

	return cfg
}

// inferKeySpec 从旧证书的公钥推断算法和长度
func inferKeySpec(cert *x509.Certificate) KeySpec {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return KeySpec{Algo: "rsa", Size: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeySpec{Algo: "ecdsa", Size: pub.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return KeySpec{Algo: "ed25519", Size: 0}
	default:
		return KeySpec{Algo: "unknown", Size: 0}
	}
}

// keyUsageToStrings x509.KeyUsage → []string
func keyUsageToStrings(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "contentCommitment") // parseKeyUsage 接受 contentCommitment/nonRepudiation
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "keyCertSign") // ← 修复：之前误写成 certSign
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "crlSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "decipherOnly")
	}
	return out
}
