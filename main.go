package main

import (
	"github.com/containerssh/auth"
	"github.com/containerssh/http"
	"github.com/containerssh/log"
	"github.com/containerssh/service"
	"github.com/containerssh/structutils"
	"sigs.k8s.io/yaml"
	"flag"
	"io/ioutil"
	"path/filepath"
	"os"
	"strings"
	"crypto/sha512"
	"encoding/hex"
	"net"
	"context"
	"os/signal"
	"syscall"
	"time"
	"fmt"
	"bytes"
)


type Config struct {
	UserFolders []string `json:"userFolders"`
	Users map[string]User `json:"users"`
	Server http.ServerConfiguration `json:"server"`
	Log log.Config `json:"log"`
	Auth Auth  `json:"auth"`
}

type User struct {
	Password	string `json:"password"`
	PublicKeys	[]string `json:"publicKeys"`
	Ips			[]string `json:ips`
	Groups		[]string `json:groups`
}

type Auth struct {
	Secret		string `json:"secret"`
}

type myHandler struct {
}

func (h *myHandler) OnPassword(
    Username string,
    Password []byte,
    RemoteAddress string,
    ConnectionID string,
) (bool, error) {
	logger.Debug(
		log.Wrap(
			nil,
			"PwdAuth",
			"User Auth",
		).Label("Username", Username).
		Label("RemoteAddress", RemoteAddress).
		Label("ConnectionID", ConnectionID),
	)
	user, ok := cfg.Users[Username]
	if !ok {
		logger.Debug(
			log.Wrap(
				nil,
				"UserNotFound",
				"User not found",
			).Label("Audit", "password").
			Label("Username", Username).
			Label("RemoteAddress", RemoteAddress).
			Label("ConnectionID", ConnectionID),
		)
		return false, nil // Username not existst 
	}

	salted :=[][]byte{ []byte(Username), []byte(cfg.Auth.Secret), Password }
	hashSum := sha512.Sum512(bytes.Join(salted,[]byte{}))
	passwordSHA := hex.EncodeToString(hashSum[:])
	if passwordSHA !=  user.Password {
		logger.Debug(
			log.Wrap(
				nil,
				"PasswordNotCorrect",
				"Password not conrrect",
			).Label("Audit", "password").
			Label("Username", Username).
			Label("Password", passwordSHA).
			Label("RemoteAddress", RemoteAddress).
			Label("ConnectionID", ConnectionID),
		)
		return false, nil // Password not correct
	} else {
		if checkIp(RemoteAddress, user.Ips){
			return true, nil // all passed
		}else{
			logger.Debug(
				log.Wrap(
					nil,
					"IPNotCorrect",
					"IP not conrrect",
				).Label("Audit", "password").
				Label("Username", Username).
				Label("Password", passwordSHA).
				Label("RemoteAddress", RemoteAddress).
				Label("ConnectionID", ConnectionID),
			)
			return false, nil // Ip not allowed
		}
	}
	logger.Debug(
		log.Wrap(
			nil,
			"NoReturn",
			"No value returned",
		).Label("Audit", "password").
		Label("Username", Username).
		Label("Password", passwordSHA).
		Label("RemoteAddress", RemoteAddress).
		Label("ConnectionID", ConnectionID),
	)
	return false, nil
}

func (h *myHandler) OnPubKey(
    Username string,
    PublicKey string,
    RemoteAddress string,
    ConnectionID string,
) (bool, error) {
	logger.Debugf("Pubkey Username %s, Address: %s, ConnectionID: %s Pubkey: %s", Username, RemoteAddress, ConnectionID, PublicKey)
	user, ok := cfg.Users[Username]
	if !ok {
		logger.Debug(
			log.Wrap(
				nil,
				"UserNotFound",
				"User not found",
			).Label("Audit", "pubKey").
			Label("Username", Username).
			Label("RemoteAddress", RemoteAddress).
			Label("ConnectionID", ConnectionID),
		)
		return false, nil // Uesr not exist
	}
	for _, pubKey := range user.PublicKeys {
		if strings.Compare(PublicKey,pubKey) == 0 {
			if checkIp(RemoteAddress, user.Ips){
				return true, nil // all passed
			} else{
				logger.Debug(
					log.Wrap(
						nil,
						"IPNotCorrect",
						"IP not conrrect",
					).Label("Audit", "pubKey").
					Label("Username", Username).
					Label("RemoteAddress", RemoteAddress).
					Label("ConnectionID", ConnectionID),
				)
				return false, nil // Ip not allowed 
			}
		}
	}
	logger.Debug(
		log.Wrap(
			nil,
			"KeyNotCorrect",
			"Key not conrrect",
		).Label("Audit", "pubKey").
		Label("Username", Username).
		Label("RemoteAddress", RemoteAddress).
		Label("ConnectionID", ConnectionID),
	)
	return false, nil // Default response
}

var (
	cfg = &Config{}
	configFlag string
	logger log.Logger
)


func checkIp(remoteIp string, ips []string) bool {
	if len(ips) == 0 { return true }
	    ip := net.ParseIP(remoteIp)
	for _, cidr := range ips {
		_, subnet, error := net.ParseCIDR(cidr)
		if error != nil { return false }
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	server, err := auth.NewServer(
		cfg.Server,
		&myHandler{},
		logger,
	)
	if err != nil {
		logger.Errorf("Server error: %v", err)
		os.Exit(-1)
	}

	lifecycle := service.NewLifecycle(server)

	go func() {
		_ = lifecycle.Run()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if _, ok := <-signals; ok {
			// ok means the channel wasn't closed, let's trigger a shutdown.
			stopContext, _ := context.WithTimeout(
				context.Background(),
				20 * time.Second,
			)
			lifecycle.Stop(stopContext)
		}
	}()
	// Wait for the service to terminate.
	err = lifecycle.Wait()
	// We are already shutting down, ignore further signals
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	// close signals channel so the signal handler gets terminated
	close(signals)

	if err != nil {
	    // Exit with a non-zero signal
	    fmt.Fprintf(
	        os.Stderr,
	        "an error happened while running the server (%v)",
	        err,
	    )
	    os.Exit(1)
	}
	os.Exit(0)

  // When done, shut down server with an optional context for the shutdown deadline
  //  lifecycle.Stop(context.Background())
}

func init() {

	flag.StringVar(&configFlag, "config", "", "configFile")

	flag.Parse()

	if configFlag != "" {
		yamlFile, err := ioutil.ReadFile(configFlag)
		if err != nil {
			panic(err)
			os.Exit(-1)
		}
		err = yaml.Unmarshal(yamlFile, &cfg)
		if err != nil {
			panic("Config parse error")
			os.Exit(-1)
		}
	}else{
		panic("Need a config file")
		os.Exit(-1)
	}

	if cfg == nil {
		panic("Config file can not be empty")
		os.Exit(-1)
	}

	structutils.Defaults(&cfg.Server)
	structutils.Defaults(&cfg.Log)

	loggerLocal, err :=  log.NewLogger(cfg.Log)
	if err != nil {
		panic(err)
	}
	logger = loggerLocal

	if cfg.UserFolders == nil { cfg.UserFolders = []string{} }
	if cfg.Users == nil { cfg.Users = make(map[string]User) }

	for _, path := range cfg.UserFolders {
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			user := User{}
			if filepath.Ext(info.Name()) == ".yml" {
				yamlFile, err := ioutil.ReadFile(configFlag)
				if err != nil {
					logger.Error(
						log.Wrap(
							err,
							"UserfileReadError",
							"Config file can not read",
						).Label("File", path),
					)
					return err
				}
				err = yaml.Unmarshal(yamlFile, &user)
				if err != nil {
					logger.Error(
						log.Wrap(
							err,
							"UserfileParseError",
							"Config file can not parse",
						).Label("File", path),
					)
					logger.Errorf("Config parse error: %s", err)
					return err
				}
				cfg.Users[strings.TrimSuffix(info.Name(), ".yml")] = user
			}
			return nil
		})
		if err != nil {
			os.Exit(-1)
		}
	}
}
