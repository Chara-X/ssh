package tunnel

import (
	"crypto/cipher"
	"hash"
)

type ConnState struct {
	Cipher cipher.Stream
	Mac    hash.Hash
	SeqNum uint32
}
