package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/bccsp/factory"

	"github.com/hyperledger/fabric/common/x509"

	"github.com/guoger/stupid/infra"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: stupid config.json 500\n")
		os.Exit(1)
	}
	config := infra.LoadConfig(os.Args[1])
	N, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	// 适配国密
	// 初始化x509模块
	if err := x509.InitX509(config.X509Plugin); err != nil {
		panic(err)
	}
	bccsp := strings.ToUpper(config.Bccsp)
	opts := &factory.FactoryOpts{
		ProviderName: bccsp,
	}
	if bccsp == "GM" {
		opts.SwOpts = &factory.SwOpts{
			Library: config.GmPlugin,
		}
	}
	if err := factory.InitFactories(opts); err != nil {
		panic(err)
	}
	crypto, err := config.LoadCrypto()
	if err != nil {
		panic(err)
	}
	raw := make(chan *infra.Elecments, 100)
	signed := make(chan *infra.Elecments, 10)
	processed := make(chan *infra.Elecments, 10)
	envs := make(chan *infra.Elecments, 10)
	done := make(chan struct{})

	assember := &infra.Assembler{Signer: crypto}
	for i := 0; i < 5; i++ {
		go assember.StartSigner(raw, signed, done)
		go assember.StartIntegrator(processed, envs, done)
	}

	proposor := infra.CreateProposers(config.NumOfConn, config.ClientPerConn, config.PeerAddr, crypto)
	proposor.Start(signed, processed, done)

	broadcaster := infra.CreateBroadcasters(config.NumOfConn, config.OrdererAddr, crypto)
	broadcaster.Start(envs, done)

	observer := infra.CreateObserver(config.PeerAddr, config.Channel, crypto)

	start := time.Now()
	go observer.Start(N, start)
	fmt.Printf("main start: %v\n", start.UTC())

	for i := 0; i < N; i++ {
		prop := infra.CreateProposal(
			crypto,
			config.Channel,
			config.Chaincode,
			config.Args...,
		)
		raw <- &infra.Elecments{Proposal: prop}
	}

	observer.Wait()
	duration := time.Since(start)
	close(done)

	fmt.Printf("end: %v", time.Now().UTC())
	fmt.Printf("tx: %d, duration: %+v, tps: %f\n", N, duration, float64(N)/duration.Seconds())
	os.Exit(0)
}
