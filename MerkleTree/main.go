package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const LEFT = "left"
const RIGHT = "right"

func main() {

	hashes := []string{
		"95cd603fe577fa9548ec0c9b50b067566fe07c8af6acba45f6196f3a15d511f6",
		"709b55bd3da0f5a838125bd0ee20c5bfdd7caba173912d4281cae816b79a201b",
		"27ca64c092a959c7edc525ed45e845b1de6a7590d173fd2fad9133c8a779a1e3",
		"1f3cb18e896256d7d6bb8c11a6ec71f005c75de05e39beae5d93bbd1e2c8b7a9",
		"41b637cfd9eb3e2f60f734f9ca44e5c1559c6f481d49d6ed6891f3e9a086ac78",
		"a8c0cce8bb067e91cf2766c26be4e5d7cfba3d3323dc19d08a834391a1ce5acf",
		"d20a624740ce1b7e2c74659bb291f665c021d202be02d13ce27feb067eeec837",
		"281b9dba10658c86d0c3c267b82b8972b6c7b41285f60ce2054211e69dd89e15",
		"df743dd1973e1c7d46968720b931af0afa8ec5e8412f9420006b7b4fa660ba8d",
		"3e812f40cd8e4ca3a92972610409922dedf1c0dbc68394fcb1c8f188a42655e2",
		"3ebc2bd1d73e4f2f1f2af086ad724c98c8030f74c0c2be6c2d6fd538c711f35c",
		"9789f4e2339193149452c1a42cded34f7a301a13196cd8200246af7cc1e33c3b",
		"aefe99f12345aabc4aa2f000181008843c8abf57ccf394710b2c48ed38e1a66a",
		"64f662d104723a4326096ffd92954e24f2bf5c3ad374f04b10fcc735bc901a4d",
		"95a73895c9c6ee0fadb8d7da2fac25eb523fc582dc12c40ec793f0c1a70893b4",
		"315987563da5a1f3967053d445f73107ed6388270b00fb99a9aaa26c56ecba2b",
		"09caa1de14f86c5c19bf53cadc4206fd872a7bf71cda9814b590eb8c6e706fbb",
		"9d04d59d713b607c81811230645ce40afae2297f1cdc1216c45080a5c2e86a5a",
		"ab8a58ff2cf9131f9730d94b9d67f087f5d91aebc3c032b6c5b7b810c47e0132",
		"c7c3f15b67d59190a6bbe5d98d058270aee86fe1468c73e00a4e7dcc7efcd3a0",
		"27ef2eaa77544d2dd325ce93299fcddef0fae77ae72f510361fa6e5d831610b2",
	}

	merkle_root := generateMerkleRoot(hashes)
	merkle_tree := generateMerkleTree(hashes)
	merkle_proof := generateMerkleProof(hashes[4], hashes)
	merkle_root_from_merkle_proof := getMerkleRootFromMerkleProof(merkle_proof)

	fmt.Println("--------------------MERKLE ROOT--------------------")
	fmt.Println(merkle_root)

	fmt.Println("--------------------MERKLE TREE--------------------")
	for _, mt := range merkle_tree {
		fmt.Println("[")
		for _, el := range mt {
			fmt.Println(el)
		}
		fmt.Println("]")
	}

	fmt.Println("--------------------MERKLE PROOF--------------------")
	for _, mp := range merkle_proof {
		fmt.Println(mp)
	}

	fmt.Println("-----------------MERKLE ROOT FROM MERKLE PROOF-----------------")
	fmt.Println(merkle_root_from_merkle_proof)

	fmt.Println("MERKLE ROOT == MERKLE ROOT FROM MERKLE PROOF: ", merkle_root == merkle_root_from_merkle_proof)
}

func generateMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}

	ensureEven(&hashes)

	combinedHashes := make([]string, 0, len(hashes)/2)

	for i := 0; i < len(hashes); i += 2 {
		hashPairConcatenated := hashes[i] + hashes[i+1]
		hash := sha256.Sum256([]byte(hashPairConcatenated))
		combinedHashes = append(combinedHashes, hex.EncodeToString(hash[:]))
	}

	if len(combinedHashes) == 1 {
		return combinedHashes[0]
	}

	res := generateMerkleRoot(combinedHashes)
	return res
}

func generateMerkleTree(hashes []string) [][]string {
	if len(hashes) == 0 {
		return [][]string{}
	}

	ensureEven(&hashes)
	tree := [][]string{hashes}
	generate(hashes, &tree)
	return tree
}

// generate recursively builds the Merkle tree from the provided hashes.
func generate(hashes []string, tree *[][]string) {

	combinedHashes := make([]string, 0)
	for i := 0; i < len(hashes); i += 2 {
		hashPairConcatenated := hashes[i] + hashes[i+1]
		hash := sha256.Sum256([]byte(hashPairConcatenated))
		combinedHashes = append(combinedHashes, hex.EncodeToString(hash[:]))
	}

	if len(combinedHashes) == 1 {
		*tree = append(*tree, combinedHashes)
		return
	}
	ensureEven(&combinedHashes)
	*tree = append(*tree, combinedHashes)
	generate(combinedHashes, tree)
}

func generateMerkleProof(hash string, hashes []string) []MerkleNode {
	if hash == "" || len(hashes) == 0 {
		return nil
	}

	tree := generateMerkleTree(hashes)
	merkleProof := []MerkleNode{
		{
			Hash:      hash,
			Direction: getLeafNodeDirectionInMerkleTree(hash, tree),
		},
	}
	hashIndex := findHashIndex(hash, tree[0])
	for level := 0; level < len(tree)-1; level++ {
		isLeftChild := hashIndex%2 == 0
		siblingDirection := LEFT
		if isLeftChild {
			siblingDirection = RIGHT
		}

		siblingIndex := hashIndex - 1
		if isLeftChild {
			siblingIndex = hashIndex + 1
		}

		siblingNode := MerkleNode{
			Hash:      tree[level][siblingIndex],
			Direction: siblingDirection,
		}
		merkleProof = append(merkleProof, siblingNode)
		hashIndex = hashIndex / 2
	}
	return merkleProof
}

func getMerkleRootFromMerkleProof(merkleProof []MerkleNode) string {
	if merkleProof == nil || len(merkleProof) == 0 {
		return ""
	}

	var merkleRootFromProof string = merkleProof[0].Hash
	for i := 1; i < len(merkleProof); i++ {
		if merkleProof[i].Direction == RIGHT {
			hash := sha256.Sum256([]byte(merkleRootFromProof + merkleProof[i].Hash))
			merkleRootFromProof = hex.EncodeToString(hash[:])
		} else {
			hash := sha256.Sum256([]byte(merkleProof[i].Hash + merkleRootFromProof))
			merkleRootFromProof = hex.EncodeToString(hash[:])
		}
	}
	return merkleRootFromProof
}

//---------------Helping functions--------------------

func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func getLeafNodeDirectionInMerkleTree(hash string, merkleTree [][]string) string {
	for i, h := range merkleTree[0] {
		if h == hash {
			if i%2 == 0 {
				return LEFT
			} else {
				return RIGHT
			}
		}
	}
	return "" // Return an empty string if the hash is not found in the leaf hash list.
}

func ensureEven(hashes *[]string) {
	if len(*hashes)%2 != 0 {
		*hashes = append(*hashes, (*hashes)[len(*hashes)-1])
	}
}

// FindHashIndex finds the index of a hash in a slice.
func findHashIndex(hash string, hashes []string) int {
	for i, h := range hashes {
		if h == hash {
			return i
		}
	}
	return -1
}

type MerkleNode struct {
	Hash      string
	Direction string
}
