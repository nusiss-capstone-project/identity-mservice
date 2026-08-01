package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/config"
	"github.com/nusiss-capstone-project/identity-mservice/server/grpc"
	"github.com/nusiss-capstone-project/identity-mservice/server/http"
	"github.com/nusiss-capstone-project/identity-mservice/server/kafka/producer"
	"github.com/nusiss-capstone-project/identity-mservice/server/log"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository"
	"github.com/nusiss-capstone-project/identity-mservice/server/repository/redis"
	"github.com/nusiss-capstone-project/identity-mservice/server/telemetry"
)

var (
	sigCh = make(chan os.Signal, 1)
)

func main() {
	config.Init()
	log.InitLogger()
	repository.Init()
	redis.Init()

	shutdownTelemetry := telemetry.Init(context.Background())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(ctx); err != nil {
			log.Logger.Errorw("telemetry shutdown failed", "error", err)
		}
	}()

	producer.Ensure()
	if config.Config.KafkaConfig == nil || !config.Config.KafkaConfig.Enabled {
		log.Logger.Info("kafka disabled")
	}

	go grpc.Init(sigCh)
	go http.Init(sigCh)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Logger.Infof("Received signal: %v, shutting down...", sig)
}
