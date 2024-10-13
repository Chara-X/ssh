package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/Chara-X/tunnel/msg"
	"golang.org/x/crypto/ssh"
)

func KeyExchange(t *Tunnel, clientVersion, serverVersion, clientKexInit, serverKexInit []byte) (k, h []byte, hostKey ssh.PublicKey, sig *ssh.Signature) {
	var ephKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var kexReq = &msg.KexRequest{
		PubKey: elliptic.Marshal(elliptic.P256(), ephKey.PublicKey.X, ephKey.PublicKey.Y),
	}
	var kexRep = t.Exchange(kexReq).(*msg.KexReply)
	var x, y, _ = unmarshalECKey(elliptic.P256(), kexRep.PubKey)
	var secret, _ = elliptic.P256().ScalarMult(x, y, ephKey.D.Bytes())
	var sha = sha256.New()
	writeString(sha, clientVersion)
	writeString(sha, serverVersion)
	writeString(sha, clientKexInit)
	writeString(sha, serverKexInit)
	writeString(sha, kexRep.HostKey)
	writeString(sha, kexReq.PubKey)
	writeString(sha, kexRep.PubKey)
	k = make([]byte, intLength(secret))
	marshalInt(k, secret)
	sha.Write(k)
	hostKey, _ = ssh.ParsePublicKey(kexRep.HostKey)
	sig = &ssh.Signature{}
	ssh.Unmarshal(kexRep.Signature, sig)
	h = sha.Sum(nil)
	return
}
func marshalInt(to []byte, n *big.Int) []byte {
	lengthBytes := to
	to = to[4:]
	length := 0
	if n.Sign() < 0 {
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			to[0] = 0xff
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	} else if n.Sign() == 0 {
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			to[0] = 0
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	}
	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)
	return to
}

var bigOne = big.NewInt(1)

func intLength(n *big.Int) int {
	length := 4
	if n.Sign() < 0 {
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bitLen := nMinus1.BitLen()
		if bitLen%8 == 0 {
			length++
		}
		length += (bitLen + 7) / 8
	} else if n.Sign() == 0 {
	} else {
		bitLen := n.BitLen()
		if bitLen%8 == 0 {
			length++
		}
		length += (bitLen + 7) / 8
	}
	return length
}
func writeString(w io.Writer, s []byte) {
	binary.Write(w, binary.BigEndian, uint32(len(s)))
	w.Write(s)
}
func unmarshalECKey(curve elliptic.Curve, pubKey []byte) (x, y *big.Int, err error) {
	x, y = elliptic.Unmarshal(curve, pubKey)
	if x == nil {
		return nil, nil, errors.New("ssh: elliptic.Unmarshal failure")
	}
	if !validateECPublicKey(curve, x, y) {
		return nil, nil, errors.New("ssh: public key not on curve")
	}
	return x, y, nil
}
func validateECPublicKey(curve elliptic.Curve, x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	if x.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if y.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if !curve.IsOnCurve(x, y) {
		return false
	}
	return true
}
