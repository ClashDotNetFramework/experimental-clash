package constant

import (
	"os"
	P "path"
	"path/filepath"
)

const Name = "clash"

// Path is used to get the configuration path
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}

	homeDir = P.Join(homeDir, ".config", Name)
	return &path{homeDir: homeDir, configFile: "config.yaml"}
}()

type path struct {
	homeDir    string
	configFile string
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}

	return path
}

func (p *path) MMDB() string {
	return P.Join(p.homeDir, "Country.mmdb")
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}
