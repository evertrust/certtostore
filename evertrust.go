//go:build windows
// +build windows

// Package certtostore handles storage for certificates.
// This file provides a high-level API layer over the existing WinCertStore
// primitives for use by EverTrust integrations.
package certtostore

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

// nCryptImportKey wraps the NCryptImportKey CNG function.
var nCryptImportKey = nCrypt.MustFindProc("NCryptImportKey")

// cngStatus converts a CNG SECURITY_STATUS HRESULT to a human-readable error.
// CNG functions return their error as the function return value (not via SetLastError),
// so the third value from syscall.Proc.Call() is always misleading for these APIs.
func cngStatus(code uintptr) error {
	// NTE_* and common CNG SECURITY_STATUS codes.
	known := map[uintptr]string{
		0x80090001: "NTE_BAD_UID",
		0x80090002: "NTE_BAD_HASH",
		0x80090003: "NTE_BAD_KEY",
		0x80090004: "NTE_BAD_LEN",
		0x80090005: "NTE_BAD_HASH_STATE",
		0x80090006: "NTE_BAD_KEY_STATE",
		0x80090007: "NTE_BAD_ALGID",
		0x80090008: "NTE_BAD_TYPE",
		0x80090009: "NTE_BAD_FLAGS",
		0x8009000A: "NTE_BAD_VER",
		0x8009000F: "NTE_EXISTS",
		0x80090010: "NTE_PERM",
		0x80090011: "NTE_NOT_FOUND",
		0x80090016: "NTE_KEYSET_NOT_DEF",
		0x80090020: "NTE_FAIL",
		0x80090028: "NTE_NO_MEMORY",
		0x80090029: "NTE_NOT_SUPPORTED",
		0x80090034: "NTE_INVALID_PARAMETER",
		0x80090035: "NTE_BUFFER_TOO_SMALL",
	}
	if name, ok := known[code]; ok {
		return fmt.Errorf("SECURITY_STATUS 0x%08X (%s)", code, name)
	}
	return fmt.Errorf("SECURITY_STATUS 0x%08X", code)
}

const (
	// nCryptExportPolicyProp is NCRYPT_EXPORT_POLICY_PROPERTY.
	nCryptExportPolicyProp = "Export Policy"

	// nCryptPkcs8PrivKeyBlob is the blob type for PKCS#8 private key import.
	nCryptPkcs8PrivKeyBlob = "PKCS8_PRIVATEKEY"

	// nCryptAllowExportFlag is NCRYPT_ALLOW_EXPORT_FLAG: key may be exported.
	nCryptAllowExportFlag = uint32(0x00000001)
)

// StoreContext specifies whether to use the current-user or local-machine store.
type StoreContext int

const (
	// MachineStore opens the local machine certificate store.
	// Requires administrator privileges for write access.
	MachineStore StoreContext = iota
	// UserStore opens the current user certificate store.
	UserStore
)

// StoreOpenOptions holds optional parameters for OpenStore.
type StoreOpenOptions struct {
	// Provider is the CNG key storage provider name.
	// Defaults to ProviderMSSoftware when empty.
	Provider string
	// Container is the key container name within the provider.
	// Used when generating or opening a specific key.
	Container string
	// LegacyKey requests a CryptoAPI-compatible copy of every key written.
	LegacyKey bool
	// ReadOnly opens the store in read-only mode.
	ReadOnly bool
}

// Store provides a high-level interface for Windows certificate store operations.
// Obtain one via OpenStore and release resources with Close.
type Store struct {
	ws        *WinCertStore
	storePtr  *uint16 // wide store name used for cert lookups
	domain    uint32  // certStoreCurrentUser or certStoreLocalMachine
}

// OpenStore opens a Windows certificate store.
//
//   - ctx selects UserStore or MachineStore.
//   - storeName is the store to open: "MY", "ROOT", "CA", or any custom name.
//   - opts configures the crypto provider, key container, and access mode.
//
// Call Close on the returned Store when finished.
func OpenStore(ctx StoreContext, storeName string, opts StoreOpenOptions) (*Store, error) {
	provider := opts.Provider
	if provider == "" {
		provider = ProviderMSSoftware
	}

	var storeFlags uint32
	if opts.ReadOnly {
		storeFlags = CertStoreReadOnly
	}

	wcsOpts := WinCertStoreOptions{
		Provider:    provider,
		Container:   opts.Container,
		LegacyKey:   opts.LegacyKey,
		CurrentUser: ctx == UserStore,
		StoreFlags:  storeFlags,
	}

	ws, err := OpenWinCertStoreWithOptions(wcsOpts)
	if err != nil {
		return nil, err
	}

	domain := certStoreLocalMachine
	if ctx == UserStore {
		domain = certStoreCurrentUser
	}

	return &Store{
		ws:       ws,
		storePtr: wide(storeName),
		domain:   domain,
	}, nil
}

// Close releases all resources held by the Store.
func (s *Store) Close() error {
	return s.ws.Close()
}

// KeyStatus describes the state of a private key associated with a certificate.
type KeyStatus struct {
	// Container is the unique NCrypt key container name; a stable identifier
	// for the key even when the key is not exportable.
	Container string
	// IsExportable indicates the key can be exported from the provider.
	IsExportable bool
	// IsHardware indicates the key is backed by a hardware security module (TPM/HSM).
	IsHardware bool
	// Signer implements crypto.Signer for the private key.
	// Always non-nil when a KeyStatus is returned.
	Signer crypto.Signer
}

// CertResult bundles a certificate with its chain and associated key status.
type CertResult struct {
	Certificate *x509.Certificate
	// Chain contains the verified certificate chains built from the leaf.
	// Each inner slice starts with the leaf and ends at a root.
	Chain []*x509.Certificate
	// KeyStatus is non-nil when a private key associated with the certificate
	// was found in the store.
	KeyStatus *KeyStatus
}

// FindCertByCommonName finds the first certificate whose subject Common Name
// contains cn in the store.
//
// Returns (nil, nil) when no matching certificate exists.
// Returns a CertResult with KeyStatus set when a private key is accessible.
func (s *Store) FindCertByCommonName(cn string) (*CertResult, error) {
	h, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return nil, fmt.Errorf("open store handle: %v", err)
	}

	certCtx, err := findCert(
		h,
		encodingX509ASN|encodingPKCS7,
		0,
		windows.CERT_FIND_SUBJECT_STR,
		wide(cn),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("FindCertByCommonName %q: %v", cn, err)
	}
	if certCtx == nil {
		return nil, nil
	}
	defer FreeCertContext(certCtx)

	cert, err := certContextToX509(certCtx)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %v", err)
	}

	if err := s.ws.resolveChains(certCtx); err != nil {
		return nil, fmt.Errorf("resolve chain: %v", err)
	}

	// Flatten the first verified chain (leaf → root).
	var chain []*x509.Certificate
	if len(s.ws.certChains) > 0 {
		chain = s.ws.certChains[0]
	}

	result := &CertResult{
		Certificate: cert,
		Chain:       chain,
	}

	// Attempt to locate the associated private key.
	k, err := s.ws.CertKey(certCtx)
	if err == nil && k != nil {
		ks, err := keyStatus(k)
		if err == nil {
			result.KeyStatus = ks
		}
	}

	return result, nil
}

// FindCertByThumbprint finds a certificate in the store by its SHA-1 thumbprint (hex-encoded).
//
// Returns (nil, nil) when no matching certificate exists.
// Returns a CertResult with KeyStatus set when a private key is accessible.
func (s *Store) FindCertByThumbprint(thumbprint string) (*CertResult, error) {
	hashBytes, err := hex.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("decode thumbprint %q: %v", thumbprint, err)
	}

	h, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return nil, fmt.Errorf("open store handle: %v", err)
	}

	hashBlob := windows.CryptHashBlob{
		Size: uint32(len(hashBytes)),
		Data: &hashBytes[0],
	}

	r, _, _ := certFindCertificateInStore.Call(
		uintptr(h),
		uintptr(encodingX509ASN|encodingPKCS7),
		0,
		uintptr(windows.CERT_FIND_SHA1_HASH),
		uintptr(unsafe.Pointer(&hashBlob)),
		0,
	)
	if r == 0 {
		return nil, nil
	}

	certCtx := (*windows.CertContext)(unsafe.Pointer(r))
	defer FreeCertContext(certCtx)

	cert, err := certContextToX509(certCtx)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %v", err)
	}

	if err := s.ws.resolveChains(certCtx); err != nil {
		return nil, fmt.Errorf("resolve chain: %v", err)
	}

	var chain []*x509.Certificate
	if len(s.ws.certChains) > 0 {
		chain = s.ws.certChains[0]
	}

	result := &CertResult{
		Certificate: cert,
		Chain:       chain,
	}

	k, err := s.ws.CertKey(certCtx)
	if err == nil && k != nil {
		ks, err := keyStatus(k)
		if err == nil {
			result.KeyStatus = ks
		}
	}

	return result, nil
}

// keyStatus builds a KeyStatus from an open Key handle.
func keyStatus(k *Key) (*KeyStatus, error) {
	isExportable := false
	buf, err := fnGetProperty(k.handle, wide(nCryptExportPolicyProp))
	if err == nil && len(buf) >= 4 {
		policy := *(*uint32)(unsafe.Pointer(&buf[0]))
		isExportable = (policy & nCryptAllowExportFlag) != 0
	}

	isHardware := false
	ph, err := getPropertyHandle(k.handle, nCryptProviderHandleProperty)
	if err == nil {
		if impl, err := getPropertyUint32(ph, nCryptImplTypeProperty); err == nil {
			isHardware = (impl & nCryptImplHardwareFlag) != 0
		}
		freeObject(ph)
	}

	return &KeyStatus{
		Container:    k.Container,
		IsExportable: isExportable,
		IsHardware:   isHardware,
		Signer:       k,
	}, nil
}

// GenerateKey generates a new private key inside the Windows key store and
// returns a crypto.Signer that can be used to create a CSR.
//
// After the signed certificate is obtained from the CA, call StoreCertWithChain
// to associate the certificate with the generated key and finalize enrollment.
func (s *Store) GenerateKey(opts GenerateOpts) (crypto.Signer, error) {
	return s.ws.Generate(opts)
}

// StoreCertWithChain imports a leaf certificate and its intermediate chain into
// the store. The leaf must already have a matching private key in the Windows
// key store (e.g. generated via GenerateKey).
//
// The leaf is stored in the store opened by OpenStore.
// Intermediates are stored in the "CA" system store for chain building.
func (s *Store) StoreCertWithChain(cert *x509.Certificate, chain []*x509.Certificate) error {
	if s.ws.isReadOnly() {
		return fmt.Errorf("store is read-only")
	}

	certCtx, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&cert.Raw[0],
		uint32(len(cert.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext: %v", err)
	}
	defer windows.CertFreeCertificateContext(certCtx)

	// Associate the matching private key already present in the key store.
	r, _, callErr := cryptFindCertificateKeyProvInfo.Call(
		uintptr(unsafe.Pointer(certCtx)),
		uintptr(uint32(0)),
		0,
	)
	if r == 0 {
		return fmt.Errorf("CryptFindCertificateKeyProvInfo: no matching key found: %v", callErr)
	}

	leafHandle, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return fmt.Errorf("open leaf store: %v", err)
	}
	if err := windows.CertAddCertificateContextToStore(
		leafHandle, certCtx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil,
	); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore (leaf): %v", err)
	}

	caHandle, err := s.ws.storeHandle(s.domain, ca)
	if err != nil {
		return fmt.Errorf("open CA store: %v", err)
	}
	for i, intermediate := range chain {
		intCtx, err := windows.CertCreateCertificateContext(
			encodingX509ASN|encodingPKCS7,
			&intermediate.Raw[0],
			uint32(len(intermediate.Raw)))
		if err != nil {
			return fmt.Errorf("CertCreateCertificateContext (intermediate %d): %v", i, err)
		}
		addErr := windows.CertAddCertificateContextToStore(
			caHandle, intCtx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil,
		)
		windows.CertFreeCertificateContext(intCtx)
		if addErr != nil {
			return fmt.Errorf("CertAddCertificateContextToStore (intermediate %d): %v", i, addErr)
		}
	}

	return nil
}

const (
	// cryptKeyProvInfoPropID is CERT_KEY_PROV_INFO_PROP_ID.
	cryptKeyProvInfoPropID = 2
	// nteExists is NTE_EXISTS: a key with this container name already exists.
	nteExists = uintptr(0x8009000F)
)

// ncryptBufferPkcsKeyName is the NCryptBuffer type for supplying a key container name.
const ncryptBufferPkcsKeyName = 45 // NCRYPTBUFFER_PKCS_KEY_NAME

// ncryptBuffer mirrors the Windows NCryptBuffer structure.
type ncryptBuffer struct {
	Size       uint32
	BufferType uint32
	Buffer     uintptr
}

// ncryptBufferDesc mirrors the Windows NCryptBufferDesc structure.
type ncryptBufferDesc struct {
	Version  uint32
	NumBufs  uint32
	Buffers  uintptr
}

// cryptKeyProvInfo mirrors the Windows CRYPT_KEY_PROV_INFO structure.
// For CNG keys dwProvType must be 0 and dwKeySpec must be CERT_NCRYPT_KEY_SPEC.
type cryptKeyProvInfo struct {
	ContainerName  *uint16
	ProvName       *uint16
	ProvType       uint32
	Flags          uint32
	ProvParamCount uint32
	ProvParams     uintptr
	KeySpec        uint32
}

// ImportCertAndKey imports a certificate, its intermediate chain, and an
// externally generated private key into the store.
//
// The private key is imported into the configured CNG provider and persisted.
// Supported key types: *rsa.PrivateKey and *ecdsa.PrivateKey.
func (s *Store) ImportCertAndKey(cert *x509.Certificate, chain []*x509.Certificate, key crypto.PrivateKey) error {
	if s.ws.isReadOnly() {
		return fmt.Errorf("store is read-only")
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key to PKCS8: %v", err)
	}

	// Use the cert SHA-1 thumbprint as the container name — stable, unique per
	// key material, and avoids having to query the name back from the handle
	// (NCryptGetProperty("Unique Name") returns NTE_NOT_SUPPORTED on some builds).
	thumb := sha1.Sum(cert.Raw)
	containerName := hex.EncodeToString(thumb[:])
	containerNameW := wide(containerName)

	// Build an NCryptBufferDesc so NCryptImportKey stores the key under our
	// chosen container name rather than an auto-generated one.
	nameBuf := ncryptBuffer{
		Size:       uint32((len(containerName) + 1) * 2), // UTF-16 bytes incl. NUL
		BufferType: ncryptBufferPkcsKeyName,
		Buffer:     uintptr(unsafe.Pointer(containerNameW)),
	}
	paramList := ncryptBufferDesc{
		Version: 0,
		NumBufs: 1,
		Buffers: uintptr(unsafe.Pointer(&nameBuf)),
	}

	// NCRYPT_PERSIST_FLAG (0x80000000) is only valid for NCryptSetProperty, not
	// NCryptImportKey — passing it produces NTE_BAD_FLAGS. NCryptImportKey persists
	// the key automatically; the only flag needed here is NCRYPT_MACHINE_KEY_FLAG
	// (carried by keyAccessFlags) when targeting the machine store.
	importFlags := uintptr(s.ws.keyAccessFlags)

	var kh uintptr
	r, _, _ := nCryptImportKey.Call(
		uintptr(s.ws.Prov),
		0, // hImportKey — not used for PKCS8
		uintptr(unsafe.Pointer(wide(nCryptPkcs8PrivKeyBlob))),
		uintptr(unsafe.Pointer(&paramList)),
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&pkcs8[0])),
		uintptr(len(pkcs8)),
		importFlags,
	)
	switch r {
	case 0:
		// Success — release our handle reference; the provider retains the key.
		defer freeObject(kh)
	case nteExists:
		// Key already persisted under this container name (retry after partial
		// failure). The container name is still valid; continue to cert import.
	default:
		return fmt.Errorf("NCryptImportKey: %w", cngStatus(r))
	}

	certCtx, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&cert.Raw[0],
		uint32(len(cert.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext: %v", err)
	}
	defer windows.CertFreeCertificateContext(certCtx)

	// Associate the imported key with this cert context by setting
	// CERT_KEY_PROV_INFO_PROP_ID directly — no provider scan needed.
	keyProvInfo := cryptKeyProvInfo{
		ContainerName: containerNameW,
		ProvName:      wide(ProviderMSSoftware),
		ProvType:      0,                       // 0 = CNG provider
		Flags:         uint32(s.ws.keyAccessFlags),
		KeySpec:       ncryptKeySpec,            // CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
	}
	rr, _, callErr := certSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(certCtx)),
		uintptr(cryptKeyProvInfoPropID),
		0,
		uintptr(unsafe.Pointer(&keyProvInfo)),
	)
	if rr == 0 {
		return fmt.Errorf("CertSetCertificateContextProperty: %v", callErr)
	}

	leafHandle, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return fmt.Errorf("open leaf store: %v", err)
	}
	if err := windows.CertAddCertificateContextToStore(
		leafHandle, certCtx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil,
	); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore (leaf): %v", err)
	}

	caHandle, err := s.ws.storeHandle(s.domain, ca)
	if err != nil {
		return fmt.Errorf("open CA store: %v", err)
	}
	for i, intermediate := range chain {
		intCtx, err := windows.CertCreateCertificateContext(
			encodingX509ASN|encodingPKCS7,
			&intermediate.Raw[0],
			uint32(len(intermediate.Raw)))
		if err != nil {
			return fmt.Errorf("CertCreateCertificateContext (intermediate %d): %v", i, err)
		}
		addErr := windows.CertAddCertificateContextToStore(
			caHandle, intCtx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil,
		)
		windows.CertFreeCertificateContext(intCtx)
		if addErr != nil {
			return fmt.Errorf("CertAddCertificateContextToStore (intermediate %d): %v", i, addErr)
		}
	}

	return nil
}

// RenewCert replaces the certificate currently identified by cn with a new
// certificate and chain. The private key is unchanged; only the cert material
// is updated.
//
// Use GenerateKey + StoreCertWithChain instead when the key must also be rotated.
func (s *Store) RenewCert(cn string, newCert *x509.Certificate, newChain []*x509.Certificate) error {
	if s.ws.isReadOnly() {
		return fmt.Errorf("store is read-only")
	}

	h, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return fmt.Errorf("open store handle: %v", err)
	}

	// Remove the existing certificate if present.
	// CertDeleteCertificateFromStore takes ownership and frees the context.
	oldCtx, err := findCert(
		h,
		encodingX509ASN|encodingPKCS7,
		0,
		windows.CERT_FIND_SUBJECT_STR,
		wide(cn),
		nil,
	)
	if err != nil {
		return fmt.Errorf("find existing certificate %q: %v", cn, err)
	}
	if oldCtx != nil {
		if err := RemoveCertByContext(oldCtx); err != nil {
			return fmt.Errorf("remove existing certificate: %v", err)
		}
	}

	return s.StoreCertWithChain(newCert, newChain)
}

// certArchivedPropID is CERT_ARCHIVED_PROP_ID: marks a cert as hidden from enumeration.
const certArchivedPropID = 19

// ApplyCertArchivalPolicy manages old certificates in the store after a renewal.
//
// It finds all certificates whose subject contains subject, excluding the one
// identified by currentThumbprint (the newly stored cert), then:
//
//   - policy == 0: archives every old cert (sets CERT_ARCHIVED_PROP_ID so it
//     remains in the store but is hidden from normal enumeration).
//   - policy > 0: sorts old certs by NotBefore descending and keeps the N most
//     recent, permanently deleting any beyond that.
func (s *Store) ApplyCertArchivalPolicy(subject string, policy int, currentThumbprint string) error {
	h, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return fmt.Errorf("open store handle: %v", err)
	}

	type entry struct {
		thumbprint    string
		notBeforeUnix int64
	}
	var entries []entry

	var prev *windows.CertContext
	for {
		ctx, err := findCert(h, encodingX509ASN|encodingPKCS7, 0, windows.CERT_FIND_SUBJECT_STR, wide(subject), prev)
		if err != nil {
			return fmt.Errorf("enumerate certs for subject %q: %v", subject, err)
		}
		if ctx == nil {
			break
		}
		cert, parseErr := certContextToX509(ctx)
		if parseErr == nil {
			// #nosec — SHA1 is mandated by the Windows cert store thumbprint convention.
			thumb := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
			if thumb != currentThumbprint {
				entries = append(entries, entry{thumb, cert.NotBefore.Unix()})
			}
		}
		prev = ctx
	}

	if len(entries) == 0 {
		return nil
	}

	if policy == 0 {
		for _, e := range entries {
			if err := s.archiveCertByThumbprint(h, e.thumbprint); err != nil {
				return err
			}
		}
		return nil
	}

	// Keep the N most recent old certs; delete the rest.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].notBeforeUnix > entries[j].notBeforeUnix
	})
	for i, e := range entries {
		if i < policy {
			continue
		}
		if err := s.deleteCertByThumbprint(h, e.thumbprint); err != nil {
			return err
		}
	}
	return nil
}

// archiveCertByThumbprint finds a certificate by its SHA-1 thumbprint and sets
// CERT_ARCHIVED_PROP_ID so it is hidden from normal enumeration but stays in the store.
func (s *Store) archiveCertByThumbprint(h windows.Handle, thumbprint string) error {
	hashBytes, err := hex.DecodeString(thumbprint)
	if err != nil {
		return fmt.Errorf("decode thumbprint: %v", err)
	}
	hashBlob := windows.CryptHashBlob{Size: uint32(len(hashBytes)), Data: &hashBytes[0]}
	r, _, _ := certFindCertificateInStore.Call(
		uintptr(h),
		uintptr(encodingX509ASN|encodingPKCS7),
		0,
		uintptr(windows.CERT_FIND_SHA1_HASH),
		uintptr(unsafe.Pointer(&hashBlob)),
		0,
	)
	if r == 0 {
		return nil // already gone
	}
	ctx := (*windows.CertContext)(unsafe.Pointer(r))
	defer windows.CertFreeCertificateContext(ctx)

	// Pass a non-NULL pvData with zero length to set the property (NULL would delete it).
	var sentinel uint32
	rr, _, callErr := certSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certArchivedPropID,
		0,
		uintptr(unsafe.Pointer(&sentinel)),
	)
	if rr == 0 {
		return fmt.Errorf("archive cert %s: %v", thumbprint[:8], callErr)
	}
	return nil
}

// deleteCertByThumbprint finds a certificate by its SHA-1 thumbprint and permanently
// removes it from the store.
func (s *Store) deleteCertByThumbprint(h windows.Handle, thumbprint string) error {
	hashBytes, err := hex.DecodeString(thumbprint)
	if err != nil {
		return fmt.Errorf("decode thumbprint: %v", err)
	}
	hashBlob := windows.CryptHashBlob{Size: uint32(len(hashBytes)), Data: &hashBytes[0]}
	r, _, _ := certFindCertificateInStore.Call(
		uintptr(h),
		uintptr(encodingX509ASN|encodingPKCS7),
		0,
		uintptr(windows.CERT_FIND_SHA1_HASH),
		uintptr(unsafe.Pointer(&hashBlob)),
		0,
	)
	if r == 0 {
		return nil // already gone
	}
	ctx := (*windows.CertContext)(unsafe.Pointer(r))
	return RemoveCertByContext(ctx) // CertDeleteCertificateFromStore takes ownership and frees ctx
}
