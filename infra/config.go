package infra

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	PeerAddr      string   `json:"peer_addr"`
	OrdererAddr   string   `json:"orderer_addr"`
	Channel       string   `json:"channel"`
	Chaincode     string   `json:"chaincode"`
	Args          []string `json:"args"`
	MSPID         string   `json:"mspid"`
	PrivateKey    string   `json:"private_key"`
	SignCert      string   `json:"sign_cert"`
	TLSCACerts    []string `json:"tls_ca_certs"`
	NumOfConn     int      `json:"num_of_conn"`
	ClientPerConn int      `json:"client_per_conn"`
	X509Plugin    string   `json:"x509_plugin"`
	Bccsp         string   `json:"bccsp"`
	GmPlugin      string   `json:"gm_plugin"`
}

func LoadConfig(f string) Config {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}
	config := Config{}
	if err = json.Unmarshal(raw, &config); err != nil {
		panic(err)
	}

	return config
}

func (c Config) LoadCrypto() (*Crypto, error) {
	conf := SignerConfig{
		MSPID:        c.MSPID,
		KeyPath:      c.PrivateKey,
		IdentityPath: c.SignCert,
		TLSCACerts:   c.TLSCACerts,
	}
	crypto, err := NewCrypto(conf)
	if err != nil {
		return nil, err
	}
	return crypto, nil
}
