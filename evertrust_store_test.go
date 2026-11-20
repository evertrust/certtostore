//go:build windows
// +build windows

package certtostore

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const testStoreName = "evertrust-certtostore-test"

// openTestStore opens a user store of its own, emptied before and after the test.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(UserStore, testStoreName, StoreOpenOptions{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	emptyTestStore(t, s)
	t.Cleanup(func() {
		emptyTestStore(t, s)
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func emptyTestStore(t *testing.T, s *Store) {
	t.Helper()
	certs, err := s.Certificates()
	if err != nil {
		t.Fatalf("Certificates: %v", err)
	}
	for _, c := range certs {
		if err := s.DeleteCertAndKey(thumbprint(c)); err != nil {
			t.Fatalf("DeleteCertAndKey: %v", err)
		}
	}
}

func thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw)
	return hex.EncodeToString(sum[:])
}

func testPFX(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfx", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testCA(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "ca", "cert.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("testdata/ca/cert.crt is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// importedCert imports a PKCS#12 of testdata/pfx and returns its certificate.
func importedCert(t *testing.T, s *Store, name string) *x509.Certificate {
	t.Helper()
	before, err := s.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportPFX(testPFX(t, name), "test", false); err != nil {
		t.Fatalf("ImportPFX %s: %v", name, err)
	}
	after, err := s.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range after {
		if !containsCert(before, c) {
			return c
		}
	}
	t.Fatalf("ImportPFX %s added no certificate", name)
	return nil
}

func containsCert(certs []*x509.Certificate, c *x509.Certificate) bool {
	for _, other := range certs {
		if other.Equal(c) {
			return true
		}
	}
	return false
}

func TestImportPFX_TheCertificateComesWithItsKey(t *testing.T) {
	s := openTestStore(t)
	cert := importedCert(t, s, "a.pfx")

	if cert.Subject.CommonName != "certtostore-test-a" {
		t.Errorf("imported %q, want certtostore-test-a", cert.Subject.CommonName)
	}
	found, err := s.FindCertByThumbprint(thumbprint(cert))
	if err != nil || found == nil || found.KeyStatus == nil {
		t.Fatalf("FindCertByThumbprint = %v, %v: want the certificate and its key", found, err)
	}
	if found.KeyStatus.IsExportable {
		t.Error("the key is exportable, the import asked for a non-exportable one")
	}
	digest := sha1.Sum([]byte("payload"))
	if _, err := found.KeyStatus.Signer.Sign(nil, digest[:], crypto.SHA1); err != nil {
		t.Errorf("Sign with the imported key: %v", err)
	}
}

func TestImportPFX_Exportable(t *testing.T) {
	s := openTestStore(t)
	if err := s.ImportPFX(testPFX(t, "a.pfx"), "test", true); err != nil {
		t.Fatal(err)
	}
	certs, err := s.Certificates()
	if err != nil || len(certs) != 1 {
		t.Fatalf("Certificates = %d certificates, %v: want 1", len(certs), err)
	}
	found, err := s.FindCertByThumbprint(thumbprint(certs[0]))
	if err != nil || found == nil || found.KeyStatus == nil {
		t.Fatalf("FindCertByThumbprint = %v, %v", found, err)
	}
	if !found.KeyStatus.IsExportable {
		t.Error("the key is not exportable")
	}
}

func TestImportPFX_RefusesWrongInput(t *testing.T) {
	s := openTestStore(t)
	if err := s.ImportPFX(nil, "test", false); err == nil {
		t.Error("ImportPFX of no data succeeded")
	}
	if err := s.ImportPFX(testPFX(t, "a.pfx"), "wrong", false); err == nil {
		t.Error("ImportPFX with a wrong password succeeded")
	}
}

func TestCertificates_ListsCertificatesWithAndWithoutKey(t *testing.T) {
	s := openTestStore(t)
	cert := importedCert(t, s, "a.pfx")
	ca := testCA(t)
	if err := s.AddCertificate(ca); err != nil {
		t.Fatal(err)
	}

	certs, err := s.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || !containsCert(certs, cert) || !containsCert(certs, ca) {
		t.Errorf("Certificates = %d certificates, want %s and %s", len(certs), cert.Subject, ca.Subject)
	}
}

func TestAddCertificate_KeepsOneCopy(t *testing.T) {
	s := openTestStore(t)
	ca := testCA(t)
	for i := 0; i < 2; i++ {
		if err := s.AddCertificate(ca); err != nil {
			t.Fatalf("AddCertificate #%d: %v", i+1, err)
		}
	}
	if err := s.DeleteCertByThumbprint(thumbprint(ca)); err != nil {
		t.Fatal(err)
	}
	found, err := s.FindCertByThumbprint(thumbprint(ca))
	if err != nil || found != nil {
		t.Errorf("after one delete FindCertByThumbprint = %v, %v: want no copy left", found, err)
	}
}

func TestAddCertificate_RefusesNoCertificate(t *testing.T) {
	s := openTestStore(t)
	if err := s.AddCertificate(nil); err == nil {
		t.Error("AddCertificate(nil) succeeded")
	}
}

func TestReadOnlyStore_RefusesWrites(t *testing.T) {
	s, err := OpenStore(UserStore, testStoreName, StoreOpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for name, err := range map[string]error{
		"AddCertificate":   s.AddCertificate(testCA(t)),
		"ImportPFX":        s.ImportPFX(testPFX(t, "a.pfx"), "test", false),
		"DeleteCertAndKey": s.DeleteCertAndKey(strings.Repeat("00", sha1.Size)),
	} {
		if err == nil {
			t.Errorf("%s on a read-only store succeeded", name)
		}
	}
}

func TestDeleteCertAndKey_KeepsAKeyAnotherCertificateUses(t *testing.T) {
	s := openTestStore(t)
	a := importedCert(t, s, "a.pfx")
	b := importedCert(t, s, "b.pfx")

	if err := s.DeleteCertAndKey(thumbprint(a)); err != nil {
		t.Fatalf("DeleteCertAndKey a: %v", err)
	}
	if found, err := s.FindCertByThumbprint(thumbprint(a)); err != nil || found != nil {
		t.Errorf("a is still in the store: %v, %v", found, err)
	}
	found, err := s.FindCertByThumbprint(thumbprint(b))
	if err != nil || found == nil || found.KeyStatus == nil {
		t.Fatalf("b lost its key: %v, %v", found, err)
	}
	if !keyExists(t, keyOf(t, s, b)) {
		t.Error("the key b shares with a was deleted with a")
	}
}

func TestDeleteCertAndKey_DeletesTheLastUseOfTheKey(t *testing.T) {
	s := openTestStore(t)
	a := importedCert(t, s, "a.pfx")
	key := keyOf(t, s, a)
	if !keyExists(t, key) {
		t.Fatalf("the imported key %s is not in its provider", key.container)
	}

	if err := s.DeleteCertAndKey(thumbprint(a)); err != nil {
		t.Fatal(err)
	}
	if keyExists(t, key) {
		t.Errorf("the key %s outlived its only certificate", key.container)
	}
}

// keyOf reads the key container the store links to the certificate.
func keyOf(t *testing.T, s *Store, c *x509.Certificate) *storeKey {
	t.Helper()
	h, err := s.handle()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := decodeThumbprint(thumbprint(c))
	if err != nil {
		t.Fatal(err)
	}
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]}
	ctx, err := windows.CertFindCertificateInStore(h, encodingX509ASN|encodingPKCS7,
		0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	if ctx == nil {
		t.Fatalf("find %s: %v", c.Subject, err)
	}
	defer windows.CertFreeCertificateContext(ctx)
	key, err := keyProvInfo(ctx)
	if err != nil || key == nil {
		t.Fatalf("keyProvInfo of %s = %v, %v", c.Subject, key, err)
	}
	return key
}

// keyExists reports whether the CNG key container can still be opened.
func keyExists(t *testing.T, k *storeKey) bool {
	t.Helper()
	if k.provType != 0 {
		t.Fatalf("key %s is a CryptoAPI key, the test expects a CNG one", k.container)
	}
	prov, err := openProvider(k.provider)
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(prov)
	var h uintptr
	r, _, _ := nCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(wide(k.container))),
		uintptr(k.keySpec), uintptr(k.flags&cryptMachineKeyset|nCryptSilentFlag))
	if r != 0 {
		return false
	}
	freeObject(h)
	return true
}

func TestDeleteCertAndKey_MissingCertificateIsNotAnError(t *testing.T) {
	s := openTestStore(t)
	if err := s.DeleteCertAndKey(strings.Repeat("ab", sha1.Size)); err != nil {
		t.Errorf("DeleteCertAndKey of a missing certificate: %v", err)
	}
}

func TestThumbprintLookups_RefuseMalformedThumbprints(t *testing.T) {
	s := openTestStore(t)
	for _, tp := range []string{"", "zz", "abcd"} {
		if _, err := s.FindCertByThumbprint(tp); err == nil {
			t.Errorf("FindCertByThumbprint(%q) succeeded", tp)
		}
		if err := s.DeleteCertByThumbprint(tp); err == nil {
			t.Errorf("DeleteCertByThumbprint(%q) succeeded", tp)
		}
		if err := s.DeleteCertAndKey(tp); err == nil {
			t.Errorf("DeleteCertAndKey(%q) succeeded", tp)
		}
	}
}

func TestKeySign_RefusesEmptyInput(t *testing.T) {
	s := openTestStore(t)
	cert := importedCert(t, s, "a.pfx")
	found, err := s.FindCertByThumbprint(thumbprint(cert))
	if err != nil || found == nil || found.KeyStatus == nil {
		t.Fatalf("FindCertByThumbprint = %v, %v", found, err)
	}
	key := found.KeyStatus.Signer
	digest := sha1.Sum([]byte("payload"))
	if _, err := key.Sign(nil, nil, crypto.SHA1); err == nil {
		t.Error("Sign of an empty digest succeeded")
	}
	if _, err := key.Sign(nil, digest[:], nil); err == nil {
		t.Error("RSA Sign without options succeeded")
	}
	if _, err := key.Sign(nil, digest[:], crypto.Hash(0)); err == nil {
		t.Error("RSA Sign with hash 0 succeeded")
	}
}
