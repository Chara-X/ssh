package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"github.com/Chara-X/ssh/msg"
)

type ECDH struct {
	curve elliptic.Curve
}

func (kex *ECDH) Client(c *Conn, rand io.Reader, magics *handshakeMagics) (*kexResult, error) {
	ephKey, err := ecdsa.GenerateKey(kex.curve, rand)
	if err != nil {
		return nil, err
	}
	kexInit := msg.KexRequest{
		PubKey: elliptic.Marshal(kex.curve, ephKey.PublicKey.X, ephKey.PublicKey.Y),
	}
	c.WritePacket(&kexInit)
	var reply msg.KexReply
	c.ReadPacket(&reply)
	x, y, err := unmarshalECKey(kex.curve, reply.PubKey)
	if err != nil {
		return nil, err
	}
	secret, _ := kex.curve.ScalarMult(x, y, ephKey.D.Bytes())
	h := ecHash(kex.curve).New()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, kexInit.PubKey)
	writeString(h, reply.PubKey)
	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)
	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   reply.HostKey,
		Signature: reply.Signature,
		Hash:      ecHash(kex.curve),
	}, nil
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
	var lengthBytes [4]byte
	lengthBytes[0] = byte(len(s) >> 24)
	lengthBytes[1] = byte(len(s) >> 16)
	lengthBytes[2] = byte(len(s) >> 8)
	lengthBytes[3] = byte(len(s))
	w.Write(lengthBytes[:])
	w.Write(s)
}

type handshakeMagics struct {
	clientVersion, serverVersion []byte
	clientKexInit, serverKexInit []byte
}

func (m *handshakeMagics) write(w io.Writer) {
	writeString(w, m.clientVersion)
	writeString(w, m.serverVersion)
	writeString(w, m.clientKexInit)
	writeString(w, m.serverKexInit)
}

type kexResult struct {
	H         []byte
	K         []byte
	HostKey   []byte
	Signature []byte
	Hash      crypto.Hash
	SessionID []byte
}

func unmarshalECKey(curve elliptic.Curve, pubkey []byte) (x, y *big.Int, err error) {
	x, y = elliptic.Unmarshal(curve, pubkey)
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
func ecHash(curve elliptic.Curve) crypto.Hash {
	bitSize := curve.Params().BitSize
	switch {
	case bitSize <= 256:
		return crypto.SHA256
	case bitSize <= 384:
		return crypto.SHA384
	}
	return crypto.SHA512
}
