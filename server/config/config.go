package config

import (
	"os"

	"github.com/spf13/viper"
)

var (
	Config = &Conf{}
)

type Conf struct {
	GrpcConfig     *GrpcConfig     `mapstructure:"grpc"`
	LogConfig      *LogConfig      `mapstructure:"log"`
	HttpConfig     *HttpConfig     `mapstructure:"http"`
	SystemConfig   *SystemConfig   `mapstructure:"system"`
	SingpassConfig *SingpassConfig `mapstructure:"singpass"`
}

type SingpassConfig struct {
	RedirectURI   string `mapstructure:"redirect_uri"`
	Scope         string `mapstructure:"scope"`
	IssuerURL     string `mapstructure:"issuer_url"`     // browser authorize base (public)
	AssertionAud  string `mapstructure:"assertion_aud"`  // client_assertion aud; optional
	TokenURL      string `mapstructure:"token_url"`
	UserInfoURL   string `mapstructure:"user_info_url"`
	JWKSURI       string `mapstructure:"jwks_uri"`
}

type HttpConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type LogConfig struct {
	Level    string `mapstructure:"level"`
	FilePath string `mapstructure:"file_path"`
}

type GrpcConfig struct {
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	ConnectTimeout int    `mapstructure:"connect_timeout"`
	MaxPoolSize    int    `mapstructure:"max_pool_size"`
}

type SystemConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

func Init() {
	workDir, _ := os.Getwd()
	viper.SetConfigName("config")
	viper.SetConfigType("yml")
	viper.AddConfigPath(workDir + "/resources")
	viper.AddConfigPath(workDir)

	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	err = viper.Unmarshal(&Config)
	if err != nil {
		panic(err)
	}
}
