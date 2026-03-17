package main

import (
	"context"
	"fmt"
	"github.com/landlock-lsm/go-landlock/landlock"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/amnezia-vpn/amneziawg-go/device"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"suah.dev/protect"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// default paths for wireproxy config file
var default_config_paths = []string {
    "/etc/wireproxy/wireproxy.conf",
    os.Getenv("HOME")+"/.config/wireproxy.conf",
}

var version = "1.0.13-dev"

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	panicIfError(protect.Pledge(promises))
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	panicIfError(protect.Unveil(path, flags))
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

// check if default config file paths exist
func configFilePath() (string, bool) {
    for _, path := range default_config_paths {
        if _, err := os.Stat(path); err == nil {
            return path, true
        }
    }
    return "", false
}

func lock(stage string) {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		unveilOrPanic("/", "r")
		unveilOrPanic(exePath, "x")
		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		pledgeOrPanic("stdio rpath inet dns proc exec")
		// Linux
		panicIfError(landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
		))
	case "boot-daemon":
	case "read-config":
		// OpenBSD
		pledgeOrPanic("stdio rpath inet dns")
	case "ready":
		// no file access is allowed from now on, only networking
		// OpenBSD
		pledgeOrPanic("stdio inet dns")
		// Linux
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies
		panicIfError(landlock.V1.BestEffort().RestrictPaths(
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		))
	default:
		panic("invalid stage")
	}
}

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	return uint16(port)
}

func lockNetwork(sections []wireproxyawg.RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxyawg.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxyawg.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxyawg.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxyawg.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	panicIfError(landlock.V4.BestEffort().RestrictNet(rules...))
}

// parseSocks5Addr парсит адрес SOCKS5 в формате:
// host:port или user:password@host:port
func parseSocks5Addr(addr string) (bindAddress, username, password string, err error) {
	// Проверяем есть ли @ (значит есть аутентификация)
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("invalid format: expected user:password@host:port")
		}
		
		// Парсим user:password
		auth := strings.SplitN(parts[0], ":", 2)
		if len(auth) != 2 {
			return "", "", "", fmt.Errorf("invalid auth format: expected user:password")
		}
		
		username = auth[0]
		password = auth[1]
		bindAddress = parts[1]
	} else {
		// Простой адрес host:port
		bindAddress = addr
	}
	
	// Проверяем что адрес содержит порт
	if _, _, err := net.SplitHostPort(bindAddress); err != nil {
		return "", "", "", fmt.Errorf("address must include port (e.g., host:port)")
	}
	
	return bindAddress, username, password, nil
}

func main() {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-s
		cancel()
	}()

	exePath := executablePath()
	lock("boot")

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		lock("boot-daemon")
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}
	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")

	config := parser.String("c", "config", &argparse.Options{Help: "Path of configuration file"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})
	
	// 🔥 ПРОСТОЙ АРГУМЕНТ: SOCKS5 прокси
	socks5Addr := parser.String("", "socks5", &argparse.Options{Help: "Start SOCKS5 proxy. Format: host:port or user:password@host:port"})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	if *printVerison {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	if *config == "" {
        if path, config_exist := configFilePath(); config_exist {
            *config = path
        } else {
            fmt.Println("configuration path is required")
            return
        }
	}

	if !*daemon {
		lock("read-config")
	}

	conf, err := wireproxyawg.ParseConfig(*config)
	if err != nil {
		log.Fatal(err)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	// Добавляем SOCKS5 из аргументов командной строки если указан
	if *socks5Addr != "" {
		bindAddress, username, password, err := parseSocks5Addr(*socks5Addr)
		if err != nil {
			log.Fatalf("Failed to parse SOCKS5 address: %v", err)
		}

		socks5Config := &wireproxyawg.Socks5Config{
			BindAddress: bindAddress,
			Username:    username,
			Password:    password,
		}
		conf.Routines = append(conf.Routines, socks5Config)
		
		if username != "" {
			log.Printf("Added SOCKS5 proxy with authentication on %s", bindAddress)
		} else {
			log.Printf("Added SOCKS5 proxy (no auth) on %s", bindAddress)
		}
	}

	lockNetwork(conf.Routines, info)

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	// Wireguard doesn't allow configuring which FD to use for logging
	// https://github.com/WireGuard/wireguard-go/blob/master/device/logger.go#L39
	// so redirect STDOUT to STDERR, we don't want to print anything to STDOUT anyways
	os.Stdout = os.NewFile(uintptr(syscall.Stderr), "/dev/stderr")
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	lock("ready")

	tun, err := wireproxyawg.StartWireguard(conf.Device, logLevel)
	if err != nil {
		log.Fatal(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
	}

	tun.StartPingIPs()

	if *info != "" {
		go func() {
			err := http.ListenAndServe(*info, tun)
			if err != nil {
				panic(err)
			}
		}()
	}

	<-ctx.Done()
}
