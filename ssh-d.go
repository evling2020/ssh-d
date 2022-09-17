package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"io/ioutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	socks5Version 	 	= uint8(5)
	ipv4Address      	= uint8(1)
	fqdnAddress      	= uint8(3)
	ipv6Address      	= uint8(4)
	connectCommand   	= uint8(1)
	noAuthentication 	= uint8(0)
	successReply 	 	= uint8(0)
	commandNotSupported = uint8(7)
	unAssigned		 	= uint8(9)
)

type arrayChainsFlag []string

func (i *arrayChainsFlag) String() string {
	return "forward address, can make a forward chain"
}
func (i *arrayChainsFlag) Set(value string) error {
	*i=append(*i,value)
	return nil
}

var (
	chainNodes 	arrayChainsFlag
	serveNode 	string
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

type Request struct {
	Version uint8
	Command uint8
	DestAddr *AddrSpec
}

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}
func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

type Node struct{
	Protocol 		string
	Username 		string
	Password 		string
	Host     		string
	PrivateKeyPath 	string
	config 			*ssh.ClientConfig
}

func parseNode(s string) (*Node,error) {
	if s==""{
		return &Node{},nil
	}
	if !strings.Contains(s, "://") {
		s = "socks://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return &Node{},err
	}
	pw,boolVar:=u.User.Password()
	if !boolVar {
		pw=""
	}
	node := Node{
		Protocol:u.Scheme,
		Username: u.User.Username(),
		Password: pw,
		Host:   u.Host,
		PrivateKeyPath: u.Path,
	}
	switch node.Protocol{
	case "socks","socks5":
		node.Protocol="socks5"
	case "ssh":
		if node.PrivateKeyPath == "" {
			node.config = &ssh.ClientConfig{
				User: node.Username,
				Auth: []ssh.AuthMethod{
					ssh.Password(node.Password),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
		} else {
			key, err :=ioutil.ReadFile(node.PrivateKeyPath)
			if err != nil {
				return &Node{},err
			}
			signer, err := ssh.ParsePrivateKey(key)
			if err != nil {
				return &Node{},err
			}
			node.config = &ssh.ClientConfig{
				User: node.Username,
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
		}
	default:
		node.Protocol=""
	}
	return &node,nil
}

func init()  {
	flag.Var(&chainNodes, "F","forward address, can make a forward chain")
	flag.StringVar(&serveNode, "L", "","listen address, can listen on multiple ports")
	flag.Parse()
}

func newSshChain(sshClientConn *ssh.Client,node *Node) (*ssh.Client ,error) {
	var err error
	if sshClientConn==nil{
		if sshClientConn, err = ssh.Dial("tcp", node.Host,node.config);err!=nil{
			return nil,err
		}
	} else {
		conn, err := sshClientConn.Dial("tcp", node.Host)
		if err!=nil{
			return nil,err
		}
		sshClientConn,err=Dialer(conn,node)
		if err!=nil{return nil,err}
	}
	return sshClientConn,nil
}

func proxiedSSHClient(proxyNode,node *Node) (*ssh.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyNode.Host, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Dial("tcp", node.Host)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, node.Host, node.config)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}

func Dialer(c net.Conn, node *Node) (*ssh.Client, error) {
	conn, chans, reqs, err := ssh.NewClientConn(c, node.Host, node.config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

func main()  {
	var sshClientConn *ssh.Client
	var exitSocksProxy *Node
	var err  error
	for index, nodeString:=range chainNodes {
		var cnode *Node
		cnode,_ = parseNode(nodeString)
		if index==0 &&cnode.Protocol=="socks5" {
			exitSocksProxy=cnode
			continue
		}
		if index==1 && exitSocksProxy!=nil{
			sshClientConn, err = proxiedSSHClient(exitSocksProxy,cnode)
			if err != nil {
				log.Fatalln(err)
			}
			continue
		}
		sshClientConn,err=newSshChain(sshClientConn,cnode)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if err:=listenAndServe("tcp",serveNode,sshClientConn);err!=nil{
		log.Fatalln(err)
	}
}

func listenAndServe(network, addr string,sshClientConn *ssh.Client) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return serve(l,sshClientConn)
}

func serve(l net.Listener,sshClientConn *ssh.Client) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleRequest(conn, sshClientConn)
	}
	return nil
}

// reply the request
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
func handleRequest(conn net.Conn , sshClientConn *ssh.Client){
	defer conn.Close()
	if err:=extractNegatiation(conn);err!=nil{
		log.Println(err)
	}
	if err:=replyNegotiation(conn);err!=nil{
		log.Println(err)
	}
	req,err:=newRequest(conn)
	if err!=nil{
		log.Println(err)
	}
	switch req.Command {
	case connectCommand:
		if err:=handleConnect(conn,req,sshClientConn);err!=nil{
			log.Println(err)
		}
	default:
		if err:=sendReply(conn,commandNotSupported,nil);err!=nil{
			log.Println( fmt.Errorf("Failed to send reply: %v", err))
		}
		log.Println(fmt.Errorf("Unsupported command: %v", req.Command))
	}
}

func handleConnect(conn net.Conn,req *Request,sshClientConn *ssh.Client) error {
	target, err := sshClientConn.Dial("tcp", req.DestAddr.Address())
	if err!=nil{
		if err := sendReply(conn, unAssigned, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	log.Println("access: ", req.DestAddr.Address())
	defer target.Close()
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	errCh := make(chan error, 2)
	go connCopy(target, conn, errCh)
	go connCopy(conn, target, errCh)
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}
	return nil
}

func connCopy(dst , src net.Conn, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func extractNegatiation(conn net.Conn)(error)  {
	negatiationHeader:=make([]byte,260)
	if _,err:=conn.Read(negatiationHeader);err!=nil{
		return fmt.Errorf("Failed to get negatiation: %v", err)
	}
	if negatiationHeader[0] != socks5Version {
		return fmt.Errorf("Unsupported socks5 version: %v", negatiationHeader[0])
	}
	return nil
}

func newRequest(conn net.Conn)(*Request,error)  {
	header:=[]byte{0,0,0}
	if _, err := conn.Read(header); err != nil {
		return nil, fmt.Errorf("Failed to get command version: %v", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}
	dest,err:=readAddrSpec(conn)
	if err!=nil{
		return nil,err
	}

	return &Request{
		Version:socks5Version,
		Command:header[1],
		DestAddr:dest,
	},nil
}

func readAddrSpec(conn net.Conn) (*AddrSpec, error) {
	d := &AddrSpec{}
	addrType := []byte{0}
	if _, err := conn.Read(addrType); err != nil {
		return nil, err
	}
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := conn.Read(addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := conn.Read(addr); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)
	case fqdnAddress:
		if _, err := conn.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := conn.Read(fqdn); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)
	default:
		return nil, unrecognizedAddrType
	}
	port := []byte{0, 0}
	if _, err := conn.Read(port); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])
	return d, nil
}

func replyNegotiation(conn net.Conn) error {
	if _, err := conn.Write([]byte{socks5Version, noAuthentication}); err != nil {
		return err
	}
	return nil
}

func sendReply(conn net.Conn, resp uint8, addr *AddrSpec) error {
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0
	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)
	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)
	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)
	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)
	_, err := conn.Write(msg)
	return err
}
