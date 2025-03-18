package home

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtls"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/c2h5oh/datasize"
	"github.com/google/go-cmp/cmp"
)

// tlsManager contains the current configuration and state of AdGuard Home TLS
// encryption.
type tlsManager struct {
	// logger is used for logging the operation of the TLS Manager.
	logger *slog.Logger

	// status is the current status of the configuration.  It is never nil.
	status *tlsConfigStatus

	// certLastMod is the last modification time of the certificate file.
	certLastMod time.Time

	confLock sync.Mutex
	conf     tlsConfigSettings

	// servePlainDNS defines if plain DNS is allowed for incoming requests.
	servePlainDNS bool
}

// newTLSManager initializes the manager of TLS configuration.  m is always
// non-nil while any returned error indicates that the TLS configuration isn't
// valid.  Thus TLS may be initialized later, e.g. via the web UI.  logger must
// not be nil.
func newTLSManager(
	ctx context.Context,
	logger *slog.Logger,
	conf tlsConfigSettings,
	servePlainDNS bool,
) (m *tlsManager, err error) {
	m = &tlsManager{
		logger:        logger,
		status:        &tlsConfigStatus{},
		conf:          conf,
		servePlainDNS: servePlainDNS,
	}

	if m.conf.Enabled {
		err = m.load(ctx)
		if err != nil {
			m.conf.Enabled = false

			return m, err
		}

		m.setCertFileTime(ctx)
	}

	return m, nil
}

// load reloads the TLS configuration from files or data from the config file.
func (m *tlsManager) load(ctx context.Context) (err error) {
	err = m.loadTLSConf(ctx, &m.conf, m.status)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	return nil
}

// WriteDiskConfig - write config
func (m *tlsManager) WriteDiskConfig(conf *tlsConfigSettings) {
	m.confLock.Lock()
	*conf = m.conf
	m.confLock.Unlock()
}

// setCertFileTime sets [tlsManager.certLastMod] from the certificate.  If there
// are errors, setCertFileTime logs them.
func (m *tlsManager) setCertFileTime(ctx context.Context) {
	if len(m.conf.CertificatePath) == 0 {
		return
	}

	fi, err := os.Stat(m.conf.CertificatePath)
	if err != nil {
		m.logger.ErrorContext(ctx, "looking up certificate path", slogutil.KeyError, err)

		return
	}

	m.certLastMod = fi.ModTime().UTC()
}

// start updates the configuration of t and starts it.
//
// TODO(s.chzhen):  Use context.
func (m *tlsManager) start(_ context.Context) {
	m.registerWebHandlers()

	m.confLock.Lock()
	tlsConf := m.conf
	m.confLock.Unlock()

	// The background context is used because the TLSConfigChanged wraps context
	// with timeout on its own and shuts down the server, which handles current
	// request.
	globalContext.web.tlsConfigChanged(context.Background(), tlsConf)
}

// reload updates the configuration and restarts the TLS manager.
func (m *tlsManager) reload(ctx context.Context) {
	m.confLock.Lock()
	tlsConf := m.conf
	m.confLock.Unlock()

	if !tlsConf.Enabled || len(tlsConf.CertificatePath) == 0 {
		return
	}

	certPath := tlsConf.CertificatePath
	fi, err := os.Stat(certPath)
	if err != nil {
		m.logger.ErrorContext(ctx, "checking certificate file", slogutil.KeyError, err)

		return
	}

	if fi.ModTime().UTC().Equal(m.certLastMod) {
		m.logger.InfoContext(ctx, "certificate file is not modified")

		return
	}

	m.logger.InfoContext(ctx, "certificate file is modified")

	m.confLock.Lock()
	err = m.load(ctx)
	m.confLock.Unlock()
	if err != nil {
		m.logger.ErrorContext(ctx, "reloading", slogutil.KeyError, err)

		return
	}

	m.certLastMod = fi.ModTime().UTC()

	err = m.reconfigureDNSServer()
	if err != nil {
		m.logger.ErrorContext(ctx, "reconfiguring dns server", slogutil.KeyError, err)
	}

	m.confLock.Lock()
	tlsConf = m.conf
	m.confLock.Unlock()

	// The background context is used because the TLSConfigChanged wraps context
	// with timeout on its own and shuts down the server, which handles current
	// request.
	globalContext.web.tlsConfigChanged(context.Background(), tlsConf)
}

// reconfigureDNSServer updates the DNS server configuration using the stored
// TLS settings.
func (m *tlsManager) reconfigureDNSServer() (err error) {
	tlsConf := &tlsConfigSettings{}
	m.WriteDiskConfig(tlsConf)

	newConf, err := newServerConfig(
		&config.DNS,
		config.Clients.Sources,
		tlsConf,
		httpRegister,
		globalContext.clients.storage,
	)
	if err != nil {
		return fmt.Errorf("generating forwarding dns server config: %w", err)
	}

	err = globalContext.dnsServer.Reconfigure(newConf)
	if err != nil {
		return fmt.Errorf("starting forwarding dns server: %w", err)
	}

	return nil
}

// loadTLSConf loads and validates the TLS configuration.  The returned error is
// also set in status.WarningValidation.
func (m *tlsManager) loadTLSConf(
	ctx context.Context,
	tlsConf *tlsConfigSettings,
	status *tlsConfigStatus,
) (err error) {
	defer func() {
		if err != nil {
			status.WarningValidation = err.Error()
			if status.ValidCert && status.ValidKey && status.ValidPair {
				// Do not return warnings since those aren't critical.
				err = nil
			}
		}
	}()

	err = loadCertificateChainData(tlsConf, status)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = loadPrivateKeyData(tlsConf, status)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = m.validateCertificates(
		ctx,
		status,
		tlsConf.CertificateChainData,
		tlsConf.PrivateKeyData,
		tlsConf.ServerNames,
	)

	return errors.Annotate(err, "validating certificate pair: %w")
}

// loadCertificateChainData loads PEM-encoded certificates chain data to the
// TLS configuration.
func loadCertificateChainData(tlsConf *tlsConfigSettings, status *tlsConfigStatus) (err error) {
	tlsConf.CertificateChainData = []byte(tlsConf.CertificateChain)
	if tlsConf.CertificatePath != "" {
		if tlsConf.CertificateChain != "" {
			return errors.Error("certificate data and file can't be set together")
		}

		tlsConf.CertificateChainData, err = os.ReadFile(tlsConf.CertificatePath)
		if err != nil {
			return fmt.Errorf("reading cert file: %w", err)
		}

		// Set status.ValidCert to true to signal the frontend that the
		// certificate opens successfully while the private key can't be opened.
		status.ValidCert = true
	}

	return nil
}

// loadPrivateKeyData loads PEM-encoded private key data to the TLS
// configuration.
func loadPrivateKeyData(tlsConf *tlsConfigSettings, status *tlsConfigStatus) (err error) {
	tlsConf.PrivateKeyData = []byte(tlsConf.PrivateKey)
	if tlsConf.PrivateKeyPath != "" {
		if tlsConf.PrivateKey != "" {
			return errors.Error("private key data and file can't be set together")
		}

		tlsConf.PrivateKeyData, err = os.ReadFile(tlsConf.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("reading key file: %w", err)
		}

		status.ValidKey = true
	}

	return nil
}

// tlsConfigStatus contains the status of a certificate chain and key pair.
type tlsConfigStatus struct {
	// Subject is the subject of the first certificate in the chain.
	Subject string `json:"subject,omitempty"`

	// Issuer is the issuer of the first certificate in the chain.
	Issuer string `json:"issuer,omitempty"`

	// KeyType is the type of the private key.
	KeyType string `json:"key_type,omitempty"`

	// NotBefore is the NotBefore field of the first certificate in the chain.
	NotBefore time.Time `json:"not_before,omitempty"`

	// NotAfter is the NotAfter field of the first certificate in the chain.
	NotAfter time.Time `json:"not_after,omitempty"`

	// WarningValidation is a validation warning message with the issue
	// description.
	WarningValidation string `json:"warning_validation,omitempty"`

	// DNSNames is the value of SubjectAltNames field of the first certificate
	// in the chain.
	DNSNames []string `json:"dns_names"`

	// ValidCert is true if the specified certificate chain is a valid chain of
	// X509 certificates.
	ValidCert bool `json:"valid_cert"`

	// ValidChain is true if the specified certificate chain is verified and
	// issued by a known CA.
	ValidChain bool `json:"valid_chain"`

	// ValidKey is true if the key is a valid private key.
	ValidKey bool `json:"valid_key"`

	// ValidPair is true if both certificate and private key are correct for
	// each other.
	ValidPair bool `json:"valid_pair"`
}

// tlsConfig is the TLS configuration and status response.
type tlsConfig struct {
	*tlsConfigStatus     `json:",inline"`
	tlsConfigSettingsExt `json:",inline"`
}

// tlsConfigSettingsExt is used to (un)marshal PrivateKeySaved field and
// ServePlainDNS field.
type tlsConfigSettingsExt struct {
	tlsConfigSettings `json:",inline"`

	// PrivateKeySaved is true if the private key is saved as a string and omit
	// key from answer.  It is used to ensure that clients don't send and
	// receive previously saved private keys.
	PrivateKeySaved bool `yaml:"-" json:"private_key_saved"`

	// ServePlainDNS defines if plain DNS is allowed for incoming requests.  It
	// is an [aghalg.NullBool] to be able to tell when it's set without using
	// pointers.
	ServePlainDNS aghalg.NullBool `yaml:"-" json:"serve_plain_dns"`
}

// handleTLSStatus is the handler for the GET /control/tls/status HTTP API.
func (m *tlsManager) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	m.confLock.Lock()
	data := tlsConfig{
		tlsConfigSettingsExt: tlsConfigSettingsExt{
			tlsConfigSettings: m.conf,
			ServePlainDNS:     aghalg.BoolToNullBool(m.servePlainDNS),
		},
		tlsConfigStatus: m.status,
	}
	m.confLock.Unlock()

	marshalTLS(w, r, data)
}

// handleTLSValidate is the handler for the POST /control/tls/validate HTTP API.
func (m *tlsManager) handleTLSValidate(w http.ResponseWriter, r *http.Request) {
	setts, err := unmarshalTLS(r)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "Failed to unmarshal TLS config: %s", err)

		return
	}

	if setts.PrivateKeySaved {
		setts.PrivateKey = m.conf.PrivateKey
	}

	if err = validateTLSSettings(setts); err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	// Skip the error check, since we are only interested in the value of
	// status.WarningValidation.
	status := &tlsConfigStatus{}
	_ = m.loadTLSConf(r.Context(), &setts.tlsConfigSettings, status)
	resp := tlsConfig{
		tlsConfigSettingsExt: setts,
		tlsConfigStatus:      status,
	}

	marshalTLS(w, r, resp)
}

// setConfig updates manager conf with the given one.
func (m *tlsManager) setConfig(
	ctx context.Context,
	newConf tlsConfigSettings,
	status *tlsConfigStatus,
	servePlain aghalg.NullBool,
) (restartHTTPS bool) {
	m.confLock.Lock()
	defer m.confLock.Unlock()

	// Reset the DNSCrypt data before comparing, since we currently do not
	// accept these from the frontend.
	//
	// TODO(a.garipov): Define a custom comparer for dnsforward.TLSConfig.
	newConf.DNSCryptConfigFile = m.conf.DNSCryptConfigFile
	newConf.PortDNSCrypt = m.conf.PortDNSCrypt
	if !cmp.Equal(m.conf, newConf, cmp.AllowUnexported(dnsforward.TLSConfig{})) {
		m.logger.InfoContext(ctx, "config has changed, restarting https server")
		restartHTTPS = true
	} else {
		m.logger.InfoContext(ctx, "config has not changed")
	}

	// Note: don't do just `t.conf = data` because we must preserve all other members of t.conf
	m.conf.Enabled = newConf.Enabled
	m.conf.ServerNames = newConf.ServerNames
	m.conf.ForceHTTPS = newConf.ForceHTTPS
	m.conf.PortHTTPS = newConf.PortHTTPS
	m.conf.PortDNSOverTLS = newConf.PortDNSOverTLS
	m.conf.PortDNSOverQUIC = newConf.PortDNSOverQUIC
	m.conf.CertificateChain = newConf.CertificateChain
	m.conf.CertificatePath = newConf.CertificatePath
	m.conf.CertificateChainData = newConf.CertificateChainData
	m.conf.PrivateKey = newConf.PrivateKey
	m.conf.PrivateKeyPath = newConf.PrivateKeyPath
	m.conf.PrivateKeyData = newConf.PrivateKeyData
	m.status = status

	if servePlain != aghalg.NBNull {
		m.servePlainDNS = servePlain == aghalg.NBTrue
	}

	return restartHTTPS
}

// handleTLSConfigure is the handler for the POST /control/tls/configure HTTP
// API.
func (m *tlsManager) handleTLSConfigure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := unmarshalTLS(r)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "Failed to unmarshal TLS config: %s", err)

		return
	}

	if req.PrivateKeySaved {
		req.PrivateKey = m.conf.PrivateKey
	}

	if err = validateTLSSettings(req); err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	status := &tlsConfigStatus{}
	err = m.loadTLSConf(ctx, &req.tlsConfigSettings, status)
	if err != nil {
		resp := tlsConfig{
			tlsConfigSettingsExt: req,
			tlsConfigStatus:      status,
		}

		marshalTLS(w, r, resp)

		return
	}

	restartHTTPS := m.setConfig(ctx, req.tlsConfigSettings, status, req.ServePlainDNS)
	m.setCertFileTime(ctx)

	if req.ServePlainDNS != aghalg.NBNull {
		func() {
			m.confLock.Lock()
			defer m.confLock.Unlock()

			config.DNS.ServePlainDNS = req.ServePlainDNS == aghalg.NBTrue
		}()
	}

	onConfigModified()

	err = m.reconfigureDNSServer()
	if err != nil {
		m.logger.ErrorContext(ctx, "reconfiguring dns server", slogutil.KeyError, err)

		aghhttp.Error(r, w, http.StatusInternalServerError, "%s", err)

		return
	}

	resp := tlsConfig{
		tlsConfigSettingsExt: req,
		tlsConfigStatus:      m.status,
	}

	marshalTLS(w, r, resp)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// The background context is used because the TLSConfigChanged wraps context
	// with timeout on its own and shuts down the server, which handles current
	// request. It is also should be done in a separate goroutine due to the
	// same reason.
	if restartHTTPS {
		go func() {
			globalContext.web.tlsConfigChanged(context.Background(), req.tlsConfigSettings)
		}()
	}
}

// validateTLSSettings returns error if the setts are not valid.
func validateTLSSettings(setts tlsConfigSettingsExt) (err error) {
	if setts.Enabled {
		err = validatePorts(
			tcpPort(config.HTTPConfig.Address.Port()),
			tcpPort(setts.PortHTTPS),
			tcpPort(setts.PortDNSOverTLS),
			tcpPort(setts.PortDNSCrypt),
			udpPort(config.DNS.Port),
			udpPort(setts.PortDNSOverQUIC),
		)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			return err
		}
	} else if setts.ServePlainDNS == aghalg.NBFalse {
		// TODO(a.garipov): Support full disabling of all DNS.
		return errors.Error("plain DNS is required in case encryption protocols are disabled")
	}

	if !webCheckPortAvailable(setts.PortHTTPS) {
		return fmt.Errorf("port %d is not available, cannot enable HTTPS on it", setts.PortHTTPS)
	}

	return nil
}

// validatePorts validates the uniqueness of TCP and UDP ports for AdGuard Home
// DNS protocols.
func validatePorts(
	bindPort, dohPort, dotPort, dnscryptTCPPort tcpPort,
	dnsPort, doqPort udpPort,
) (err error) {
	tcpPorts := aghalg.UniqChecker[tcpPort]{}
	addPorts(
		tcpPorts,
		tcpPort(bindPort),
		tcpPort(dohPort),
		tcpPort(dotPort),
		tcpPort(dnscryptTCPPort),
	)

	err = tcpPorts.Validate()
	if err != nil {
		return fmt.Errorf("validating tcp ports: %w", err)
	}

	udpPorts := aghalg.UniqChecker[udpPort]{}
	addPorts(udpPorts, udpPort(dnsPort), udpPort(doqPort))

	err = udpPorts.Validate()
	if err != nil {
		return fmt.Errorf("validating udp ports: %w", err)
	}

	return nil
}

// validateCertChain verifies certs using the first as the main one and others
// as intermediate.  srvName stands for the expected DNS name.
func (m *tlsManager) validateCertChain(
	ctx context.Context,
	certs []*x509.Certificate,
	srvName string,
) (err error) {
	main, others := certs[0], certs[1:]

	pool := x509.NewCertPool()
	for _, cert := range others {
		pool.AddCert(cert)
	}

	othersLen := len(others)
	if othersLen > 0 {
		m.logger.InfoContext(
			ctx,
			"verifying certificate chain: got an intermediate cert",
			"num", othersLen,
		)
	}

	opts := x509.VerifyOptions{
		DNSName:       srvName,
		Roots:         globalContext.tlsRoots,
		Intermediates: pool,
	}
	_, err = main.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate does not verify: %w", err)
	}

	return nil
}

// errNoIPInCert is the error that is returned from [tlsManager.parseCertChain]
// if the leaf certificate doesn't contain IPs.
const errNoIPInCert errors.Error = `certificates has no IP addresses; ` +
	`DNS-over-TLS won't be advertised via DDR`

// parseCertChain parses the certificate chain from raw data, and returns it.
// If ok is true, the returned error, if any, is not critical.
func (m *tlsManager) parseCertChain(
	ctx context.Context,
	chain []byte,
) (parsedCerts []*x509.Certificate, ok bool, err error) {
	m.logger.DebugContext(ctx, "parsing certificate chain", "size", datasize.ByteSize(len(chain)))

	var certs []*pem.Block
	for decoded, pemblock := pem.Decode(chain); decoded != nil; {
		if decoded.Type == "CERTIFICATE" {
			certs = append(certs, decoded)
		}

		decoded, pemblock = pem.Decode(pemblock)
	}

	parsedCerts, err = parsePEMCerts(certs)
	if err != nil {
		return nil, false, err
	}

	m.logger.InfoContext(ctx, "parsing multiple pem certificates", "num", len(parsedCerts))

	if !aghtls.CertificateHasIP(parsedCerts[0]) {
		err = errNoIPInCert
	}

	return parsedCerts, true, err
}

// parsePEMCerts parses multiple PEM-encoded certificates.
func parsePEMCerts(certs []*pem.Block) (parsedCerts []*x509.Certificate, err error) {
	for i, cert := range certs {
		var parsed *x509.Certificate
		parsed, err = x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate at index %d: %w", i, err)
		}

		parsedCerts = append(parsedCerts, parsed)
	}

	if len(parsedCerts) == 0 {
		return nil, errors.Error("empty certificate")
	}

	return parsedCerts, nil
}

// validatePKey validates the private key, returning its type.  It returns an
// empty string if error occurs.
func validatePKey(pkey []byte) (keyType string, err error) {
	var key *pem.Block

	// Go through all pem blocks, but take first valid pem block and drop the
	// rest.
	for decoded, pemblock := pem.Decode([]byte(pkey)); decoded != nil; {
		if decoded.Type == "PRIVATE KEY" || strings.HasSuffix(decoded.Type, " PRIVATE KEY") {
			key = decoded

			break
		}

		decoded, pemblock = pem.Decode(pemblock)
	}

	if key == nil {
		return "", errors.Error("no valid keys were found")
	}

	_, keyType, err = parsePrivateKey(key.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	if keyType == keyTypeED25519 {
		return "", errors.Error(
			"ED25519 keys are not supported by browsers; " +
				"did you mean to use X25519 for key exchange?",
		)
	}

	return keyType, nil
}

// validateCertificates processes certificate data and its private key.  status
// must not be nil, since it's used to accumulate the validation results.  Other
// parameters are optional.
func (m *tlsManager) validateCertificates(
	ctx context.Context,
	status *tlsConfigStatus,
	certChain []byte,
	pkey []byte,
	serverNames []string,
) (err error) {
	// Check only the public certificate separately from the key.
	if len(certChain) > 0 {
		var certs []*x509.Certificate
		certs, status.ValidCert, err = m.parseCertChain(ctx, certChain)
		if !status.ValidCert {
			// Don't wrap the error, since it's informative enough as is.
			return err
		}

		mainCert := certs[0]
		status.Subject = mainCert.Subject.String()
		status.Issuer = mainCert.Issuer.String()
		status.NotAfter = mainCert.NotAfter
		status.NotBefore = mainCert.NotBefore
		status.DNSNames = mainCert.DNSNames
		for _, serverName := range serverNames {
			if chainErr := m.validateCertChain(ctx, certs, serverName); chainErr != nil {
				// Let self-signed certs through and don't return this error to set
				// its message into the status.WarningValidation afterwards.
				err = chainErr
				status.ValidChain = false
				break
			} else {
				status.ValidChain = true
			}
		}
	}

	// Validate the private key by parsing it.
	if len(pkey) > 0 {
		var keyErr error
		status.KeyType, keyErr = validatePKey(pkey)
		if keyErr != nil {
			// Don't wrap the error, since it's informative enough as is.
			return keyErr
		}

		status.ValidKey = true
	}

	// If both are set, validate together.
	if len(certChain) > 0 && len(pkey) > 0 {
		_, pairErr := tls.X509KeyPair(certChain, pkey)
		if pairErr != nil {
			return fmt.Errorf("certificate-key pair: %w", pairErr)
		}

		status.ValidPair = true
	}

	return err
}

// Key types.
const (
	keyTypeECDSA   = "ECDSA"
	keyTypeED25519 = "ED25519"
	keyTypeRSA     = "RSA"
)

// Attempt to parse the given private key DER block.  OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA.  We try all three.
//
// TODO(a.garipov): Find out if this version of parsePrivateKey from the stdlib
// is actually necessary.
func parsePrivateKey(der []byte) (key crypto.PrivateKey, typ string, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, keyTypeRSA, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, keyTypeRSA, nil
		case *ecdsa.PrivateKey:
			return key, keyTypeECDSA, nil
		case ed25519.PrivateKey:
			return key, keyTypeED25519, nil
		default:
			return nil, "", fmt.Errorf(
				"tls: found unknown private key type %T in PKCS#8 wrapping",
				key,
			)
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return key, keyTypeECDSA, nil
	}

	return nil, "", errors.Error("tls: failed to parse private key")
}

// unmarshalTLS handles base64-encoded certificates transparently
func unmarshalTLS(r *http.Request) (tlsConfigSettingsExt, error) {
	data := tlsConfigSettingsExt{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return data, fmt.Errorf("failed to parse new TLS config json: %w", err)
	}

	if data.CertificateChain != "" {
		var cert []byte
		cert, err = base64.StdEncoding.DecodeString(data.CertificateChain)
		if err != nil {
			return data, fmt.Errorf("failed to base64-decode certificate chain: %w", err)
		}

		data.CertificateChain = string(cert)
		if data.CertificatePath != "" {
			return data, fmt.Errorf("certificate data and file can't be set together")
		}
	}

	if data.PrivateKey != "" {
		var key []byte
		key, err = base64.StdEncoding.DecodeString(data.PrivateKey)
		if err != nil {
			return data, fmt.Errorf("failed to base64-decode private key: %w", err)
		}

		data.PrivateKey = string(key)
		if data.PrivateKeyPath != "" {
			return data, fmt.Errorf("private key data and file can't be set together")
		}
	}

	return data, nil
}

func marshalTLS(w http.ResponseWriter, r *http.Request, data tlsConfig) {
	if data.CertificateChain != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(data.CertificateChain))
		data.CertificateChain = encoded
	}

	if data.PrivateKey != "" {
		data.PrivateKeySaved = true
		data.PrivateKey = ""
	}

	aghhttp.WriteJSONResponseOK(w, r, data)
}

// registerWebHandlers registers HTTP handlers for TLS configuration.
func (m *tlsManager) registerWebHandlers() {
	httpRegister(http.MethodGet, "/control/tls/status", m.handleTLSStatus)
	httpRegister(http.MethodPost, "/control/tls/configure", m.handleTLSConfigure)
	httpRegister(http.MethodPost, "/control/tls/validate", m.handleTLSValidate)
}
