package infra

import (
	"encoding/pem"
	"io/ioutil"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	proto_utils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
)

type SignerConfig struct {
	MSPID        string
	IdentityPath string
	KeyPath      string
	TLSCACerts   []string
}

type Crypto struct {
	key        bccsp.Key
	Creator    []byte
	TLSCACerts [][]byte
}

func (si *Crypto) NewSignatureHeader() (*common.SignatureHeader, error) {
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		return nil, err
	}
	return &common.SignatureHeader{
		Creator: si.Creator,
		Nonce:   nonce,
	}, nil
}

func (si *Crypto) Serialize() ([]byte, error) {
	return si.Creator, nil
}

// NewSigner creates a new Signer out of the given configuration
func NewCrypto(conf SignerConfig) (*Crypto, error) {
	sId, err := serializeIdentity(conf.IdentityPath, conf.MSPID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := loadPrivateKey(conf.KeyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	tlsCerts, err := getTLSCACerts(conf.TLSCACerts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Crypto{
		Creator:    sId,
		key:        key,
		TLSCACerts: tlsCerts,
	}, nil
}

func (si *Crypto) Sign(msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("msg (to sign) required")
	}
	digest, err := factory.GetDefault().Hash(msg, &bccsp.SHA256Opts{})
	if err != nil {
		return nil, err
	}
	signature, err := factory.GetDefault().Sign(si.key, digest, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func serializeIdentity(clientCert string, mspID string) ([]byte, error) {
	b, err := ioutil.ReadFile(clientCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sId := &msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: b,
	}
	return proto_utils.MarshalOrPanic(sId), nil
}

func loadPrivateKey(file string) (bccsp.Key, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bl, _ := pem.Decode(b)
	if bl == nil {
		return nil, errors.Errorf("failed to decode PEM block from %s", file)
	}
	key, err := factory.GetDefault().KeyImport(bl.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{true})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse private key from %s", file)
	}
	return key, nil
}

func getTLSCACerts(files []string) ([][]byte, error) {
	var certs [][]byte
	for _, f := range files {
		in, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}

		certs = append(certs, in)
	}

	return certs, nil
}
