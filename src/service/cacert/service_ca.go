package cacert

import (
	"crypto/x509"
	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/uuid4"
)

// ---------- 初始化根 CA ----------

func InitRootCA(dao *models.DB, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestParamsError, "invalid config", err)
	}

	key, err := createKey(cfg.Key.Algo, cfg.Key.Size)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "create key failed", err)
	}
	der, err := signCert(key, nil, nil, cfg, true)
	if err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestError, "sign CA failed", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse cert failed", err)
	}
	encKey, encPassphrase, err := encryptPrivateKey(key)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "encrypt private key failed", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certFP := calcCertFingerprint(cert)
	keyFP, err := calcPubKeyFingerprint(key)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "calc key fingerprint failed", err)
	}

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	cfgJSON, err := marshalConfig(cfg)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "marshal config failed", err)
	}

	certRec := models.Certificate{
		CertID:   certID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: nil,
		Pathlev:  PathLevCA,
		Genre:    GenreRoot,
		HasKey:   1,
		IssueCfg: cfgJSON,
	}
	keyRec := &models.PrivateKey{
		KeyID:       keyID,
		PrivateKey:  encKey,
		Passphrase:  encPassphrase,
		Fingerprint: &keyFP,
		CreateTime:  now,
	}

	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	if err := dao.SaveCertBundle(certRec, keyRec, version); err != nil {
		return "", ErrInternal(answer.EcodeError, "save cert bundle failed", err)
	}
	return certID, nil
}

// ---------- 签发中间 CA ----------

func IssueIntermediateSvc(dao *models.DB, parentID string, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestParamsError, "invalid config", err)
	}

	parent, err := dao.GetCertificateByCertID(parentID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query parent failed", err)
	}
	if parent == nil {
		return "", ErrNotFound(answer.EcodeIssuer404, "parent CA not found", nil)
	}
	if parent.Genre != GenreRoot && parent.Genre != GenreInter {
		return "", ErrBadRequest(answer.EcodeNonCACertificate, "parent must be a CA certificate", nil)
	}

	parentVer, err := dao.GetLatestVersion(parentID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query parent version failed", err)
	}
	if parentVer == nil {
		return "", ErrNotFound(answer.EcodeVersion404, "parent version not found", nil)
	}
	if parentVer.KeyID == nil {
		return "", ErrBadRequest(answer.EcodeCACannotSign, "parent CA has no private key, cannot sign", nil)
	}

	parentKey, err := dao.GetPrivateKeyByKeyID(*parentVer.KeyID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query parent key failed", err)
	}
	if parentKey == nil {
		return "", ErrNotFound(answer.EcodePrivateKey404, "parent key not found", nil)
	}
	parentCert, err := parseCertPEM(*parentVer.Cert)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse parent cert failed", err)
	}
	parentSigner, err := decryptPrivateKey(parentKey.PrivateKey, parentKey.Passphrase)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "decrypt parent key failed", err)
	}

	key, err := createKey(cfg.Key.Algo, cfg.Key.Size)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "create key failed", err)
	}
	der, err := signCert(key, parentCert, parentSigner, cfg, true)
	if err != nil {
		return "", ErrBadRequest(answer.EcodeInvalidRequestError, "sign intermediate failed", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse cert failed", err)
	}
	encKey, encPassphrase, err := encryptPrivateKey(key)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "encrypt private key failed", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certFP := calcCertFingerprint(cert)
	keyFP, err := calcPubKeyFingerprint(key)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "calc key fingerprint failed", err)
	}

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	cfgJSON, err := marshalConfig(cfg)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "marshal config failed", err)
	}

	certRec := models.Certificate{
		CertID:   certID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: &parentID,
		Pathlev:  PathLevInter,
		Genre:    GenreInter,
		HasKey:   1,
		IssueCfg: cfgJSON,
	}
	keyRec := &models.PrivateKey{
		KeyID:       keyID,
		PrivateKey:  encKey,
		Passphrase:  encPassphrase,
		Fingerprint: &keyFP,
		CreateTime:  now,
	}

	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	if err := dao.SaveCertBundle(certRec, keyRec, version); err != nil {
		return "", ErrInternal(answer.EcodeError, "save cert bundle failed", err)
	}
	return certID, nil
}
