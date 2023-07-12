package common

import (
	"fmt"

	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type ProofWriter struct {
	Keys   [][]byte
	Values [][]byte
}

func (p *ProofWriter) Put(key []byte, value []byte) error {
	p.Keys = append(p.Keys, key)
	p.Values = append(p.Values, value)
	return nil
}

func (p *ProofWriter) Delete(key []byte) error {
	return nil
}

func GetTransactionProof(bk *types.Block, index int) (nodes [][]byte, keyIndex, leafRlpPrefix []byte, err error) {
	var indexBuf []byte
	keyIndex = rlp.AppendUint64(indexBuf[:0], uint64(index))

	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	tt := trie.NewEmpty(db)
	txRootHash := types.DeriveSha(bk.Transactions(), tt)
	if txRootHash != bk.TxHash() {
		log.Errorf("tx root hash mismatch, blk: %d, index: %d, tx root hash: %x != %x", bk.NumberU64(), index, txRootHash, bk.TxHash())
	}
	log.Infof("blk: %d, index: %d, tx root hash: %x", bk.NumberU64(), index, txRootHash)

	proofWriter := &ProofWriter{
		Keys:   [][]byte{},
		Values: [][]byte{},
	}
	err = tt.Prove(keyIndex, 0, proofWriter)
	if err != nil {
		return
	}
	var leafRlp [][]byte
	leafValue := proofWriter.Values[len(proofWriter.Values)-1]
	err = rlp.DecodeBytes(leafValue, &leafRlp)
	if err != nil {
		return
	}
	if len(leafRlp) != 2 {
		err = fmt.Errorf("invalid leaf rlp len:%d, index:%d, bk:%s", len(leafRlp), index, bk.Number().String())
		return
	}
	return proofWriter.Values, keyIndex, leafValue[:len(leafValue)-len(leafRlp[1])], nil
}

func GetReceiptProof(bk *types.Block, receipts types.Receipts, index int) (nodes [][]byte, keyIndex, leafRlpPrefix []byte, err error) {
	var indexBuf []byte
	keyIndex = rlp.AppendUint64(indexBuf[:0], uint64(index))

	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	tt := trie.NewEmpty(db)
	receiptRootHash := types.DeriveSha(receipts, tt)
	if receiptRootHash != bk.ReceiptHash() {
		log.Errorf("tx root hash mismatch, blk: %d, index: %d, tx root hash: %x != %x", bk.NumberU64(), index, receiptRootHash, bk.ReceiptHash())
	}
	log.Infof("blk: %d, index: %d, receipt root hash: %x", bk.NumberU64(), index, receiptRootHash)

	proofWriter := &ProofWriter{
		Keys:   [][]byte{},
		Values: [][]byte{},
	}
	err = tt.Prove(keyIndex, 0, proofWriter)
	if err != nil {
		return
	}
	var leafRlp [][]byte
	leafValue := proofWriter.Values[len(proofWriter.Values)-1]
	err = rlp.DecodeBytes(leafValue, &leafRlp)
	if err != nil {
		return
	}
	if len(leafRlp) != 2 {
		err = fmt.Errorf("invalid leaf rlp len:%d, index:%d, bk:%s", len(leafRlp), index, bk.Number().String())
		return
	}
	return proofWriter.Values, keyIndex, leafValue[:len(leafValue)-len(leafRlp[1])], nil
}
