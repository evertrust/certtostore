//go:build windows
// +build windows

package certtostore

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	certAddEncodedCertificateToStore  = crypt32.MustFindProc("CertAddEncodedCertificateToStore")
	certEnumSystemStore               = crypt32.MustFindProc("CertEnumSystemStore")
	certGetCertificateContextProperty = crypt32.MustFindProc("CertGetCertificateContextProperty")
	nCryptDeleteKey                   = nCrypt.MustFindProc("NCryptDeleteKey")
)

const (
	certKeyProvInfoPropID   = 2          // CERT_KEY_PROV_INFO_PROP_ID
	certStoreAddUseExisting = 2          // CERT_STORE_ADD_USE_EXISTING
	certStoreAddReplace     = 3          // CERT_STORE_ADD_REPLACE_EXISTING
	cryptMachineKeyset      = 0x20       // CRYPT_MACHINE_KEYSET, same bit as NCRYPT_MACHINE_KEY_FLAG
	cryptUserKeyset         = 0x1000     // CRYPT_USER_KEYSET
	cryptExportable         = 0x1        // CRYPT_EXPORTABLE
	nCryptSilentFlag        = 0x40       // NCRYPT_SILENT_FLAG
	nteBadKeyset            = 0x80090016 // NTE_BAD_KEYSET
)

// decodeThumbprint decodes a hex SHA-1 thumbprint, refusing any other length.
func decodeThumbprint(thumbprint string) ([]byte, error) {
	hash, err := hex.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("decode thumbprint %q: %v", thumbprint, err)
	}
	if len(hash) != sha1.Size {
		return nil, fmt.Errorf("thumbprint %q is not a SHA-1 hash", thumbprint)
	}
	return hash, nil
}

// handle returns the store's handle, opened once and closed by Close.
func (s *Store) handle() (windows.Handle, error) {
	h, err := s.ws.storeHandle(s.domain, s.storePtr)
	if err != nil {
		return 0, fmt.Errorf("open store handle: %v", err)
	}
	return h, nil
}

func (s *Store) writableHandle() (windows.Handle, error) {
	if s.ws.isReadOnly() {
		return 0, errors.New("store is read-only")
	}
	return s.handle()
}

// Certificates returns every certificate of the store, whether a private key is linked to it or not.
func (s *Store) Certificates() ([]*x509.Certificate, error) {
	h, err := s.handle()
	if err != nil {
		return nil, err
	}
	var (
		certs []*x509.Certificate
		ctx   *windows.CertContext
	)
	for {
		// CertEnumCertificatesInStore frees the previous context.
		ctx, err = windows.CertEnumCertificatesInStore(h, ctx)
		if ctx == nil {
			if endOfStore(err) {
				return certs, nil
			}
			return nil, fmt.Errorf("enumerate store: %v", err)
		}
		cert, err := certContextToX509(ctx)
		if err != nil {
			windows.CertFreeCertificateContext(ctx)
			return nil, fmt.Errorf("read certificate: %v", err)
		}
		certs = append(certs, cert)
	}
}

func endOfStore(err error) bool {
	return errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) || errors.Is(err, windows.ERROR_NO_MORE_FILES)
}

// AddCertificate adds a certificate without key to the store, unless the store already holds it.
func (s *Store) AddCertificate(cert *x509.Certificate) error {
	if cert == nil || len(cert.Raw) == 0 {
		return errors.New("no certificate to add")
	}
	h, err := s.writableHandle()
	if err != nil {
		return err
	}
	r, _, err := certAddEncodedCertificateToStore.Call(
		uintptr(h),
		encodingX509ASN|encodingPKCS7,
		uintptr(unsafe.Pointer(&cert.Raw[0])),
		uintptr(len(cert.Raw)),
		certStoreAddUseExisting,
		0)
	if r == 0 {
		return fmt.Errorf("CertAddEncodedCertificateToStore: %v", err)
	}
	return nil
}

// ImportPFX imports the certificates of a PKCS#12 blob into the store, replacing the ones it
// already holds, with their keys in the key set of the store's location. The provider and the
// friendly name come from the attributes of the PKCS#12.
func (s *Store) ImportPFX(data []byte, password string, exportable bool) error {
	if len(data) == 0 {
		return errors.New("no PKCS#12 to import")
	}
	h, err := s.writableHandle()
	if err != nil {
		return err
	}
	pw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	flags := uint32(cryptUserKeyset)
	if s.domain == certStoreLocalMachine {
		flags = cryptMachineKeyset
	}
	if exportable {
		flags |= cryptExportable
	}
	pfx, err := windows.PFXImportCertStore(&windows.CryptDataBlob{Size: uint32(len(data)), Data: &data[0]}, pw, flags)
	if err != nil {
		return fmt.Errorf("PFXImportCertStore: %v", err)
	}
	defer windows.CertCloseStore(pfx, windows.CERT_CLOSE_STORE_FORCE_FLAG)
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(pfx, ctx)
		if ctx == nil {
			if endOfStore(err) {
				return nil
			}
			return fmt.Errorf("enumerate PKCS#12: %v", err)
		}
		if err := windows.CertAddCertificateContextToStore(h, ctx, certStoreAddReplace, nil); err != nil {
			windows.CertFreeCertificateContext(ctx)
			return fmt.Errorf("CertAddCertificateContextToStore: %v", err)
		}
	}
}

// DeleteCertAndKey deletes the certificate with the given thumbprint, then its key container,
// unless a certificate of a system store of the same location still uses it, as after a renewal
// that kept the key. A missing certificate or key is not an error.
func (s *Store) DeleteCertAndKey(thumbprint string) error {
	hash, err := decodeThumbprint(thumbprint)
	if err != nil {
		return err
	}
	h, err := s.writableHandle()
	if err != nil {
		return err
	}
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]}
	ctx, err := windows.CertFindCertificateInStore(h, encodingX509ASN|encodingPKCS7,
		0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	if ctx == nil {
		if endOfStore(err) {
			return nil
		}
		return fmt.Errorf("find %s: %v", thumbprint, err)
	}
	key, err := keyProvInfo(ctx)
	if err != nil {
		windows.CertFreeCertificateContext(ctx)
		return fmt.Errorf("read the key of %s: %v", thumbprint, err)
	}
	// CertDeleteCertificateFromStore frees the context, even when it fails.
	if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
		return fmt.Errorf("delete %s: %v", thumbprint, err)
	}
	if key == nil {
		return nil
	}
	inUse, err := keyInUse(key, s.domain)
	if err != nil {
		return fmt.Errorf("key %s of %s kept: %v", key.container, thumbprint, err)
	}
	if inUse {
		return nil
	}
	if err := key.delete(); err != nil {
		return fmt.Errorf("key %s of %s kept: %v", key.container, thumbprint, err)
	}
	return nil
}

// storeKey is the key container a certificate is linked to. A zero provType is a CNG provider,
// any other a CryptoAPI one.
type storeKey struct {
	container string
	provider  string
	provType  uint32
	flags     uint32
	keySpec   uint32
}

func (k *storeKey) sameContainer(other *storeKey) bool {
	return strings.EqualFold(k.container, other.container) && strings.EqualFold(k.provider, other.provider)
}

// keyProvInfo returns the key linked to the certificate, or nil when it has none.
func keyProvInfo(ctx *windows.CertContext) (*storeKey, error) {
	var size uint32
	r, _, err := certGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
			return nil, nil
		}
		return nil, err
	}
	buf := make([]byte, size)
	r, _, err = certGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, err
	}
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	return &storeKey{
		container: windows.UTF16PtrToString(info.ContainerName),
		provider:  windows.UTF16PtrToString(info.ProvName),
		provType:  info.ProvType,
		flags:     info.Flags,
		keySpec:   info.KeySpec,
	}, nil
}

// delete deletes the key container. A container already gone is not an error.
func (k *storeKey) delete() error {
	container, err := windows.UTF16PtrFromString(k.container)
	if err != nil {
		return err
	}
	provider, err := windows.UTF16PtrFromString(k.provider)
	if err != nil {
		return err
	}
	if k.provType != 0 {
		var h windows.Handle
		err := windows.CryptAcquireContext(&h, container, provider, k.provType,
			windows.CRYPT_DELETEKEYSET|windows.CRYPT_SILENT|k.flags&cryptMachineKeyset)
		if errors.Is(err, syscall.Errno(nteBadKeyset)) {
			return nil
		}
		return err
	}
	var prov, handle uintptr
	if r, _, _ := nCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(provider)), 0); r != 0 {
		return fmt.Errorf("NCryptOpenStorageProvider: %v", cngStatus(r))
	}
	defer nCryptFreeObject.Call(prov)
	r, _, _ := nCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(container)),
		uintptr(k.keySpec), uintptr(k.flags&cryptMachineKeyset|nCryptSilentFlag))
	if r == nteBadKeyset {
		return nil
	}
	if r != 0 {
		return fmt.Errorf("NCryptOpenKey: %v", cngStatus(r))
	}
	// NCryptDeleteKey frees the handle only when it succeeds.
	if r, _, _ := nCryptDeleteKey.Call(handle, nCryptSilentFlag); r != 0 {
		nCryptFreeObject.Call(handle)
		return fmt.Errorf("NCryptDeleteKey: %v", cngStatus(r))
	}
	return nil
}

var (
	systemStoresMu sync.Mutex
	systemStores   []string
	// One callback for the process: Windows allows a limited number of them.
	enumSystemStoreCallback = windows.NewCallback(func(name *uint16, _ uint32, _, _, _ uintptr) uintptr {
		systemStores = append(systemStores, windows.UTF16PtrToString(name))
		return 1
	})
)

func systemStoreNames(domain uint32) ([]string, error) {
	systemStoresMu.Lock()
	defer systemStoresMu.Unlock()
	systemStores = nil
	if r, _, err := certEnumSystemStore.Call(uintptr(domain), 0, 0, enumSystemStoreCallback); r == 0 {
		return nil, fmt.Errorf("CertEnumSystemStore: %v", err)
	}
	return systemStores, nil
}

// keyInUse reports whether a certificate of a system store of the domain uses the key container.
func keyInUse(key *storeKey, domain uint32) (bool, error) {
	names, err := systemStoreNames(domain)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		inUse, err := storeUsesKey(domain, name, key)
		if err != nil || inUse {
			return inUse, err
		}
	}
	return false, nil
}

func storeUsesKey(domain uint32, storeName string, key *storeKey) (bool, error) {
	st, err := newStoreHandle(domain, wide(storeName), CertStoreReadOnly|windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if err != nil {
		return false, fmt.Errorf("open store %s: %v", storeName, err)
	}
	defer st.Close()
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(*st.handle, ctx)
		if ctx == nil {
			if endOfStore(err) {
				return false, nil
			}
			return false, fmt.Errorf("read store %s: %v", storeName, err)
		}
		other, err := keyProvInfo(ctx)
		if err != nil || (other != nil && other.sameContainer(key)) {
			windows.CertFreeCertificateContext(ctx)
			if err != nil {
				return false, fmt.Errorf("read store %s: %v", storeName, err)
			}
			return true, nil
		}
	}
}
