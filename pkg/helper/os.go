package h

import (
	"crypto/x509"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/vault-thirteen/auxie/errors"
)

const (
	OS_Windows = "windows"
)

const (
	DLL_Crypt32 = "crypt32.dll"
)

const (
	FuncName_CertOpenSystemStoreW        = "CertOpenSystemStoreW"
	FuncName_CertEnumCertificatesInStore = "CertEnumCertificatesInStore"
	FuncName_CertCloseStore              = "CertCloseStore"
)

const (
	Windows_CertStoreName_Root = "ROOT"
)

//	typedef struct _CERT_CONTEXT {
//	  DWORD      dwCertEncodingType;
//	  BYTE       *pbCertEncoded;
//	  DWORD      cbCertEncoded;
//	  ...
//	}
type certContext struct {
	dwCertEncodingType uint32
	pbCertEncoded      *byte
	cbCertEncoded      uint32
}

func GetSystemRootCertificates() (caCerts []*x509.Certificate, err error) {
	switch runtime.GOOS {
	case OS_Windows:
		return getSystemRootCertificates_windows()
	default:
		return nil, errors.ErrorFromFormattedText(Errf_UnsupportedOS, runtime.GOOS)
	}
}
func getSystemRootCertificates_windows() (caCerts []*x509.Certificate, err error) {
	crypt32 := syscall.NewLazyDLL(DLL_Crypt32)
	procCertOpenSystemStoreW := crypt32.NewProc(FuncName_CertOpenSystemStoreW)
	procCertEnumCertificatesInStore := crypt32.NewProc(FuncName_CertEnumCertificatesInStore)
	procCertCloseStore := crypt32.NewProc(FuncName_CertCloseStore)

	var storeName *uint16
	storeName, err = syscall.UTF16PtrFromString(Windows_CertStoreName_Root)
	if err != nil {
		return nil, err
	}

	// CertOpenSystemStoreW(0, "ROOT")
	var hCertStore uintptr
	hCertStore, _, err = procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(storeName)))
	if hCertStore == 0 {
		return nil, err
	}
	defer func() {
		r1, _, derr := procCertCloseStore.Call(hCertStore, 0)
		if r1 == 0 {
			err = errors.Combine(err, derr)
		}
	}()

	var pCertContext uintptr

	var cert *x509.Certificate
	for {
		pCertContext, _, _ = procCertEnumCertificatesInStore.Call(hCertStore, pCertContext)
		if pCertContext == 0 {
			break
		}

		ctx := (*certContext)(unsafe.Pointer(pCertContext))
		derBytes := unsafe.Slice(ctx.pbCertEncoded, ctx.cbCertEncoded)

		cert, err = x509.ParseCertificate(derBytes)
		if err != nil {
			continue
		}

		if cert.IsCA {
			caCerts = append(caCerts, cert)
		}
	}

	return caCerts, nil
}
