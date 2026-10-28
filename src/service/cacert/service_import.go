package cacert

import (
	"crypto"
	"crypto/x509"
	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/uuid4"
)

// ---------- 导入 CA ----------

// ImportCAReq 导入 CA 请求
type ImportCAReq struct {
	Title    *string `json:"title"`
	CertPem  string  `json:"certPem"`
	KeyPem   string  `json:"keyPem"`
	IssuerID string  `json:"issuerId"`
}

// ImportCAResp 导入 CA 响应
type ImportCAResp struct {
	CertID  string `json:"certId"`
	Genre   int    `json:"genre"`
	Pathlev int    `json:"pathlev"`
}

// ImportCASvc 导入 CA 证书（根 CA 或中间 CA）
//   - 只允许 IsCA=true 的证书
//   - 中间 CA 必须有父 CA
//   - 只支持 X.509 证书和 PKCS#8 私钥
func ImportCASvc(dao *models.DB, req *ImportCAReq) (*ImportCAResp, error) {
	// 1. 解析证书
	cert, err := parseSingleCertPEM(req.CertPem)
	if err != nil {
		return nil, ErrBadRequest(answer.EcodeInvalidCertPEM, "parse cert failed", err)
	}

	// 1.5 证书指纹判重
	certFP := calcCertFingerprint(cert)
	if existing, err := dao.GetVersionByFingerprint(certFP); err != nil {
		return nil, ErrInternal(answer.EcodeError, "check cert fingerprint failed", err)
	} else if existing != nil {
		return nil, ErrConflict(answer.EcodeResourceExists, "certificate already imported", nil)
	}

	// 2. 必须是 CA
	if !cert.IsCA {
		return nil, ErrBadRequest(answer.EcodeNonCACertificate, "only CA certificates can be imported", nil)
	}

	// 3. 判断根 CA 还是中间 CA
	isRoot := cert.Subject.String() == cert.Issuer.String()
	var genre, pathlev int
	if isRoot {
		genre = GenreRoot
		pathlev = PathLevCA
	} else {
		genre = GenreInter
		pathlev = PathLevInter
	}

	// 4. 私钥处理（可选）
	var signer crypto.Signer
	var keyFP string
	hasKey := req.KeyPem != ""

	if hasKey {
		signer, err = parsePKCS8Key(req.KeyPem)
		if err != nil {
			return nil, ErrBadRequest(answer.EcodeInvalidKeyPEM, "parse key failed", err)
		}

		keyFP, err = calcPubKeyFingerprint(signer)
		if err != nil {
			return nil, ErrInternal(answer.EcodeError, "calc key fingerprint failed", err)
		}
		if existing, err := dao.GetPrivateKeyByFingerprint(keyFP); err != nil {
			return nil, ErrInternal(answer.EcodeError, "check key fingerprint failed", err)
		} else if existing != nil {
			return nil, ErrConflict(answer.EcodeResourceExists, "private key already imported", nil)
		}

		if err := matchCertAndKey(cert, signer); err != nil {
			return nil, ErrBadRequest(answer.EcodeKeyCertMismatch, "key/cert mismatch", err)
		}
	}

	// 5. 校验 KeyUsage 有 certSign
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrBadRequest(answer.EcodeNonCACertificate, "CA certificate must have certSign key usage", nil)
	}

	// 6. 处理 parentId
	var parentID *string
	if !isRoot {
		if req.IssuerID != "" {
			parent, err := dao.GetCertificateByCertID(req.IssuerID)
			if err != nil {
				return nil, ErrInternal(answer.EcodeError, "query issuer failed", err)
			}
			if parent == nil {
				return nil, ErrNotFound(answer.EcodeIssuer404, "issuerId not found", nil)
			}
			if parent.Genre != GenreRoot && parent.Genre != GenreInter {
				return nil, ErrBadRequest(answer.EcodeNonCACertificate, "issuer must be a CA", nil)
			}
			parentID = &parent.CertID
		} else {
			parent, err := dao.FindCASubject(cert.Issuer.String())
			if err != nil {
				return nil, ErrInternal(answer.EcodeError, "find parent failed", err)
			}
			if parent == nil {
				return nil, ErrNotFound(answer.EcodeParentCA404, "parent CA not found, please specify issuerId", nil)
			}
			parentID = &parent.CertID
		}
	}

	// 7. 组装记录
	certID := uuid4.Uuid4Str()
	now := nowMillis()
	subject := formatSubject(cert.Subject)
	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	state := StateValid
	rev := 1

	hasKeyInt8 := int8(0)
	if hasKey {
		hasKeyInt8 = 1
	}

	certRec := models.Certificate{
		CertID:   certID,
		Title:    req.Title,
		Subject:  &subject,
		ParentID: parentID,
		Pathlev:  pathlev,
		Genre:    genre,
		HasKey:   hasKeyInt8,
		IssueCfg: "{}",
	}

	var keyRec *models.PrivateKey
	var keyIDPtr *string

	if hasKey {
		keyID := uuid4.Uuid4Str()
		keyIDPtr = &keyID

		encKey, encPassphrase, err := encryptPrivateKey(signer)
		if err != nil {
			return nil, ErrInternal(answer.EcodeError, "encrypt key failed", err)
		}

		keyRec = &models.PrivateKey{
			KeyID:       keyID,
			PrivateKey:  encKey,
			Passphrase:  encPassphrase,
			Fingerprint: &keyFP,
			CreateTime:  now,
		}
	}

	certPEM := string(pemEncode("CERTIFICATE", cert.Raw))
	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          keyIDPtr,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(certPEM),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	if err := dao.SaveCertBundle(certRec, keyRec, version); err != nil {
		return nil, ErrInternal(answer.EcodeError, "save cert bundle failed", err)
	}

	return &ImportCAResp{
		CertID:  certID,
		Genre:   genre,
		Pathlev: pathlev,
	}, nil
}
