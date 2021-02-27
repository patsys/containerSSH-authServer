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
//	"context"
	"io"
)


type Config struct {
	UserFolders []string `json:"userFolders"`
	Users map[string]User `json:"users"`
	Server http.ServerConfiguration `json:"server"`
	Log log.Config `json:"log"`
}

type User struct {
	Password	string `json:"password"`
	PublicKeys	[]string `json:"publicKeys"`
	Ips			[]string `json:ips`
	Groups		[]string `json:groups`
}

type sureFireWriter struct {
	backend io.Writer
}

type myHandler struct {
}

func (s *sureFireWriter) Write(p []byte) (n int, err error) {
	n, err = s.backend.Write(p)
	if err != nil {
		// Ignore errors
		return len(p), nil
	}
	return n, nil
}

func (h *myHandler) OnPassword(
    Username string,
    Password []byte,
    RemoteAddress string,
    ConnectionID string,
) (bool, error) {
	logger.Debugf("Password Username %s, Address: %s, ConnectionID: %s Password: %s", Username, RemoteAddress, ConnectionID, string(Password))
	user, ok := cfg.Users[Username]
	if !ok {
		logger.Errorf("Audit(password): Username %s, Address: %s, CennectionID: %s", Username, RemoteAddress, ConnectionID)
		logger.Debugf("Password Username(%s) not exist", Username)
		return false, nil // Username not existst 
	}

	hashSum := sha512.Sum512(Password)
	passwordSHA := hex.EncodeToString(hashSum[:])
	if passwordSHA !=  user.Password {
		logger.Errorf("Audit(password): Username %s, Address: %s, CennectionID: %s", Username, RemoteAddress, ConnectionID)
		logger.Debugf("Password Password(%s) wrong", passwordSHA)
		return false, nil // Password not correct
	} else {
		if checkIp(RemoteAddress, user.Ips){
			return true, nil // all passed
		}else{
			logger.Errorf("Audit(password): Username %s, Address: %s, CennectionID: %s", Username, RemoteAddress, ConnectionID)
			logger.Debugf("Password IP(%s) not allowed", RemoteAddress)
			return false, nil // Ip not allowed
		}
	}
	logger.Errorf("Audit(password): Username %s, Address: %s, CennectionID: %s", Username, RemoteAddress, ConnectionID)
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
		logger.Errorf("Audit(pubKey): Username %s, Address: %s, CennectionID: %s", Username, RemoteAddress, ConnectionID)
		logger.Debugf("Pubkey Username(%s) not exist", Username)
		return false, nil // Uesr not exist
	}
	for _, pubKey := range user.PublicKeys {
		if strings.Compare(PublicKey,pubKey) == 0 {
			if checkIp(RemoteAddress, user.Ips){
				return true, nil // all passed
			} else{
				logger.Errorf("Audit: Username %s, Address: %s", Username, RemoteAddress)
				logger.Debugf("Pubkey IP(%s) not allowed", RemoteAddress)
				return false, nil // Ip not allowed 
			}
		}
	}
	logger.Errorf("Audit: Username %s, Address: %s", Username, RemoteAddress)
	logger.Debugf("Pubkey Key(%s) not exist", PublicKey)
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

func runServer(lifecycle service.Lifecycle){
	if err := lifecycle.Run(); err != nil {
		panic(err)
		logger.Errorf("Server stoppt: %v", err)
	}
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
   runServer(lifecycle)

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

	loggerLocal, err :=  log.NewFactory(&sureFireWriter{os.Stdout}).Make(cfg.Log, "")
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
					logger.Errorf("Cannot get config file %s Get err   #%v ", path, err)
					return err
				}
				err = yaml.Unmarshal(yamlFile, &user)
				if err != nil {
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
