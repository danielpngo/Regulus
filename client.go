package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	Password      string
	PKEPrivateKey userlib.PrivateKeyType
	DSPrivateKey  userlib.PrivateKeyType // keys

	// IV

	// You can a	d other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).

}

type Ciphertext struct {
	Ciphertext []byte
	Mac_Sign   []byte
}

type File struct {
	Filename             string
	Owner                string
	UsersWAccess         map[string]string
	UsersNotAddedByOwner map[string]string // key: recipient, val: sender
	FirstNodeUUID        userlib.UUID      // pointer to LL beginning
	LastNodeUUID         userlib.UUID      // pointer to end of LL
}

type Metadata struct {
	FileUUID         userlib.UUID
	FileOwner        string
	OriginalFilename string
	ConDecKey        []byte
	ConMacKey        []byte
	StrDecKey        []byte
	StrMacKey        []byte
}

type Node struct {
	CurrNodeUUID userlib.UUID
	NextNodeUUID userlib.UUID
	NodeNum      int // Current node number we're on (also used to get new datastore key)
	// Each file saved as a diff UUID
}

type MetadataKey struct {
	MetaUUID userlib.UUID
}

/*
	Wrap/Unwrap Hierarchy
	1. Unwrap CipherUser
	2. Unwrap User
	3. Unwrap CipherFileList
	4. Unwrap File List
	5. Unwrap CipherFile
	6. Unwrap File
	7. Unwrap CipherNode
	8. Unwrap Node

	Wrap/Unwrap Pattern
	Get from Datastore
	1. Compare Mac --> return
	2. Decrypt Ciphertext
	3. Unmarshal inro Struct
	4. Change Struct
	5. Re Encrypt Struct
	6. Re Mac Struct
	7. Re Marshal Struct
	8. Store Struct in Data Store

*/

// NOTE: The following methods have toy (insecure!) implementations.

// COMPLETE
func InitUser(username string, password string) (userdataptr *User, err error) {

	// _________________________________________________________________
	// Check Edge Cases

	_, ok := userlib.KeystoreGet(username)

	// check if user doesn't exist
	if ok {
		return nil, errors.New(strings.ToTitle("User already taken"))
	}

	// check if username is empty
	if len(username) <= 0 {
		return nil, errors.New(strings.ToTitle("Invalid Username"))
	}

	// _________________________________________________________________
	// Create User Struct

	// create Public Private encryption key Pair
	pubKey, priKey, errPKEKeyGen := userlib.PKEKeyGen()
	if errPKEKeyGen != nil {
		return nil, errPKEKeyGen
	}

	// create Public Private signature key Pair
	priDS, pubDS, errDS := userlib.DSKeyGen()
	if errDS != nil {
		return nil, errDS
	}

	// create user struct
	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.PKEPrivateKey = priKey
	userdata.DSPrivateKey = priDS

	// _________________________________________________________________
	// Create Keys + UUID

	// Generate salt
	salt := userlib.Hash([]byte(username))

	// Generate Encryption Key and IV
	argKey := userlib.Argon2Key([]byte(password), salt, 32)
	EncKey := argKey[:16]
	MacKey := argKey[16:32]

	// UUID for datastore : create new UUID from first 16b of userStruct JSON
	// how long is UUID?? and [:] start at 0??
	UUID, errUUID := uuid.FromBytes(salt[:16])
	if errUUID != nil {
		return nil, errUUID
	}

	pubUUID := username + string(salt)

	//____________________________________________________________________________
	// Prepare User Struct

	userBytes, errJSON := json.Marshal(userdata)
	if errJSON != nil {
		return nil, errJSON
	}

	encUser, macUser, errEMUser := EncryptAndMac(EncKey, MacKey, userlib.RandomBytes(16), userBytes)
	if errEMUser != nil {
		return nil, errEMUser
	}

	wrappedUser, errWrapUser := WrapCipher(encUser, macUser)
	if errWrapUser != nil {
		return nil, errWrapUser
	}

	// _________________________________________________________________
	// Store DS Public Key and User Struct

	// store DS public key in keystore
	userlib.KeystoreSet(username, pubKey)

	// store PKE public key in keystore
	userlib.KeystoreSet(pubUUID, pubDS)

	// store in Datastore
	userlib.DatastoreSet(UUID, wrappedUser)

	// return
	return &userdata, nil
}

// COMPLETE
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check if password is correct
	// Create new user struct
	// Check if it matches
	// Create pointer/new instance

	// returns error if no initialized user
	_, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New(strings.ToTitle("No initialized user for given username"))
	}

	// _________________________________________________________________
	// Create Keys + UUID

	// Generate salt
	salt := userlib.Hash([]byte(username))

	// Generate Encryption Key and IV
	argKey := userlib.Argon2Key([]byte(password), salt, 32)
	DecKey := argKey[:16]
	MacKey := argKey[16:32]

	// UUID for datastore : create new UUID from first 16b of userStruct JSON
	UUID, errUUID := uuid.FromBytes(salt[:16])
	if errUUID != nil {
		return nil, errUUID
	}

	// _________________________________________________________________
	// Get User Struct

	wrappedUser, ok2 := userlib.DatastoreGet(UUID)
	if !ok2 {
		return nil, errors.New(strings.ToTitle("No initialized user for given username"))
	}

	//____________________________________________________________________________
	// Unprepare UserStruct

	cipherUser, errCipherUser := UnwrapCipher(wrappedUser)
	if errCipherUser != nil {
		return nil, errCipherUser
	}

	plaintext, errMacDec := CheckMacAndDecrypt(DecKey, MacKey, cipherUser.Ciphertext, cipherUser.Mac_Sign)
	if errMacDec != nil {
		return nil, errMacDec
	}

	var user User

	// Unmarshal the user struct
	unmar_plaintextErr := json.Unmarshal(plaintext, &user)
	if unmar_plaintextErr != nil {
		return
	}

	//____________________________________________________________________________
	// Check if Password Matches

	usr := username == user.Username
	pswd := password == user.Password
	if !usr {
		return nil, errors.New(strings.ToTitle("Username is incorrect"))
	} else if !pswd {
		return nil, errors.New(strings.ToTitle("Password is incorrect"))
	} else {
		return &user, nil
	}
}

// COMPLETE
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// check filename exists??
	if len(filename) <= 0 {
		return errors.New(strings.ToTitle("Filename is too short"))
	}

	//assume already got User Struct

	//____________________________________________________________________________
	// KeyGen

	// generate encryptionKey
	argonFileKey := userlib.Argon2Key([]byte(userdata.Password), userlib.Hash([]byte(filename+userdata.Username)), 16)
	hashKeys, errHashKDF := userlib.HashKDF(argonFileKey, []byte("encryption"))
	if errHashKDF != nil {
		return errHashKDF
	}

	// Create encryption and mac keys
	conEncKey := hashKeys[:16]
	conMacKey := hashKeys[16:32]
	strEncKey := hashKeys[32:48]
	strMacKey := hashKeys[48:64]

	//____________________________________________________________________________
	// Create UUIDs

	// Create file content UUID
	conUUID, conErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + fmt.Sprint(0)))[:16])
	if conErr != nil {
		return conErr
	}

	// Create struct UUIDS
	fileUUID, fileErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strEncKey)))[:16])
	if fileErr != nil {
		return fileErr
	}
	nodeUUID, nodeErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey)))[:16])
	if nodeErr != nil {
		return nodeErr
	}
	node1UUID, node1Err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey) + fmt.Sprint(1)))[:16])
	if node1Err != nil {
		return node1Err
	}

	// Create metadata UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return metaKeyErr
	}

	metaUUID := uuid.New()

	//____________________________________________________________________________
	// Prepare File Contents

	// Enc + Mac file contents
	encFile, macFile, errFile := EncryptAndMac(conEncKey, conMacKey, userlib.RandomBytes(16), content)
	if errFile != nil {
		return errFile
	}
	// Wrap file contents
	wrapFile, wrapErr := WrapCipher(encFile, macFile)
	if wrapErr != nil {
		return wrapErr
	}

	//____________________________________________________________________________
	// Create new Structs

	// File Struct
	var filedata File
	filedata.Filename = filename
	filedata.Owner = userdata.Username
	filedata.UsersWAccess = make(map[string]string)
	filedata.UsersNotAddedByOwner = make(map[string]string)
	filedata.FirstNodeUUID = nodeUUID
	filedata.LastNodeUUID = node1UUID

	// Node Struct
	var nodedata Node
	nodedata.CurrNodeUUID = conUUID
	nodedata.NextNodeUUID = node1UUID
	nodedata.NodeNum = 0

	var nodedata1 Node
	nodedata1.CurrNodeUUID = uuid.Nil
	nodedata1.NextNodeUUID = uuid.Nil
	nodedata1.NodeNum = 1

	// Metadata Struct
	var meta Metadata
	meta.FileUUID = fileUUID
	meta.FileOwner = userdata.Username
	meta.OriginalFilename = filename
	meta.ConDecKey = conEncKey
	meta.ConMacKey = conMacKey
	meta.StrDecKey = strEncKey
	meta.StrMacKey = strMacKey

	// Metadata Key Struct
	var metaKey MetadataKey
	metaKey.MetaUUID = metaUUID

	//____________________________________________________________________________
	// Prepare new Structs

	// Marshal, Encrypt, Mac, and Wrap File Struct
	marFile, errMarFile := json.Marshal(filedata)
	if errMarFile != nil {
		return errMarFile
	}
	encMarFile, macMarFile, errEncFile := EncryptAndMac(strEncKey, strMacKey, userlib.RandomBytes(16), marFile)
	if errEncFile != nil {
		return errEncFile
	}
	wrapMarFile, errWrapFile := WrapCipher(encMarFile, macMarFile)
	if errWrapFile != nil {
		return errWrapFile
	}

	// Marshal, Encrypt, Mac, and Wrap Node Struct
	marNode, errMarNode := json.Marshal(nodedata)
	if errMarNode != nil {
		return errMarNode
	}
	encMarNode, macMarNode, errEncNode := EncryptAndMac(strEncKey, strMacKey, userlib.RandomBytes(16), marNode)
	if errEncNode != nil {
		return errEncNode
	}
	wrapMarNode, errWrapNode := WrapCipher(encMarNode, macMarNode)
	if errWrapNode != nil {
		return errWrapNode
	}

	// Marshal, Encrypt, Mac, and Wrap Node 1 Struct
	marNode1, errMarNode1 := json.Marshal(nodedata1)
	if errMarNode1 != nil {
		return errMarNode1
	}
	encMarNode1, macMarNode1, errEncNode1 := EncryptAndMac(strEncKey, strMacKey, userlib.RandomBytes(16), marNode1)
	if errEncNode1 != nil {
		return errEncNode1
	}
	wrapMarNode1, errWrapNode1 := WrapCipher(encMarNode1, macMarNode1)
	if errWrapNode1 != nil {
		return errWrapNode1
	}

	// Marshal, Encrypt, Mac, and Wrap Metadata Struct
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	marMeta, marMetaErr := json.Marshal(meta)
	if marMetaErr != nil {
		return marMetaErr
	}
	encMeta, macMeta, errMeta := EncryptAndMac(metaEncKey, metaMacKey, userlib.RandomBytes(16), marMeta)
	if errMeta != nil {
		return errMeta
	}
	wrapMeta, wrapMetaErr := WrapCipher(encMeta, macMeta)
	if wrapMetaErr != nil {
		return wrapMetaErr
	}

	// Marshal, Encrypt, Mac, and Wrap MetadataKey Struct
	marMetaKey, marMetaKeyErr := json.Marshal(metaKey)
	if marMetaKeyErr != nil {
		return marMetaKeyErr
	}
	encMetaKey, macMetaKey, errMetaKey := EncryptAndMac(metaEncKey, metaMacKey, userlib.RandomBytes(16), marMetaKey)
	if errMetaKey != nil {
		return errMetaKey
	}
	wrapMetaKey, wrapMetaKeyErr := WrapCipher(encMetaKey, macMetaKey)
	if wrapMetaKeyErr != nil {
		return wrapMetaKeyErr
	}

	//____________________________________________________________________________
	// Store Files and Structs in Datastore

	// Store file contents
	userlib.DatastoreSet(conUUID, wrapFile)

	// Store file struct
	userlib.DatastoreSet(fileUUID, wrapMarFile)

	// Store node struct
	userlib.DatastoreSet(nodeUUID, wrapMarNode)

	// Store node struct
	userlib.DatastoreSet(node1UUID, wrapMarNode1)

	// Store metadata
	userlib.DatastoreSet(metaUUID, wrapMeta)

	// Store key to metadata
	userlib.DatastoreSet(metaKeyUUID, wrapMetaKey)

	return nil
}

// COMPLETE
func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	//____________________________________________________________________________
	// Create Keys

	//____________________________________________________________________________
	// Get Metadata Key

	// Create metadata key UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return metaKeyErr
	}

	metaKey, ok0 := userlib.DatastoreGet(metaKeyUUID)
	if !ok0 {
		return errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata key
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	unwrapKey, unwrapKeyErr := UnwrapCipher(metaKey)
	if unwrapKeyErr != nil {
		return unwrapKeyErr
	}
	decKey, decKeyErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapKey.Ciphertext, unwrapKey.Mac_Sign)
	if decKeyErr != nil {
		return decKeyErr
	}
	var metaKeydata MetadataKey
	unmarKeyErr := json.Unmarshal(decKey, &metaKeydata)
	if unmarKeyErr != nil {
		return unmarKeyErr
	}

	metaUUID := metaKeydata.MetaUUID

	//____________________________________________________________________________
	// Get Metadata and Dec Keys

	wrapMeta, ok1 := userlib.DatastoreGet(metaUUID)
	if !ok1 {
		return errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata
	unwrapMeta, unwrapMetaErr := UnwrapCipher(wrapMeta)
	if unwrapMetaErr != nil {
		return unwrapMetaErr
	}
	decMeta, decMetaErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapMeta.Ciphertext, unwrapMeta.Mac_Sign)
	if decMetaErr != nil {
		return decMetaErr
	}
	var metadata Metadata
	unmarMetaErr := json.Unmarshal(decMeta, &metadata)
	if unmarMetaErr != nil {
		return unmarMetaErr
	}

	// Get rand keys
	ownerFileName := metadata.OriginalFilename
	owner := metadata.FileOwner
	randConEnc := metadata.ConDecKey
	randConMac := metadata.ConMacKey
	randEncKey := metadata.StrDecKey
	randMacKey := metadata.StrMacKey

	//____________________________________________________________________________
	// Create File UUID and get File

	fileUUID, fileErr := uuid.FromBytes(userlib.Hash([]byte(ownerFileName + owner + string(randEncKey)))[:16])
	if fileErr != nil {
		return fileErr
	}

	wrapFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New(strings.ToTitle("Filename is incorrect"))
	}

	//____________________________________________________________________________
	// Get raw file struct

	unwrapFile, unwrapErr := UnwrapCipher(wrapFile)
	if unwrapErr != nil {
		return unwrapErr
	}

	decFile, decErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrapFile.Ciphertext, unwrapFile.Mac_Sign)
	if decErr != nil {
		return decErr
	}

	var filedata File

	unmarErr := json.Unmarshal(decFile, &filedata)
	if unmarErr != nil {
		return unmarErr
	}

	//____________________________________________________________________________
	// Prepare Empty Node

	lastNodeUUID := filedata.LastNodeUUID
	wrapLastNode, ok2 := userlib.DatastoreGet(lastNodeUUID)
	if !ok2 {
		return errors.New(strings.ToTitle("Cannot retrieve last node"))
	}

	unwrapLast, unwrapLastErr := UnwrapCipher(wrapLastNode)
	if unwrapLastErr != nil {
		return unwrapLastErr
	}

	decLast, decLastErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrapLast.Ciphertext, unwrapLast.Mac_Sign)
	if decLastErr != nil {
		return decLastErr
	}

	var lastnodedata Node

	unmarLastErr := json.Unmarshal(decLast, &lastnodedata)
	if unmarLastErr != nil {
		return unmarLastErr
	}

	//____________________________________________________________________________
	// Edit Empty Node

	// Last empty node moves one space over
	lastnodedata.NodeNum = lastnodedata.NodeNum + 1
	lastnodedata.CurrNodeUUID = uuid.Nil
	lastnodedata.NextNodeUUID = uuid.Nil

	// Generate new UUID of new node
	newLastUUID, newLastErr := uuid.FromBytes(userlib.Hash([]byte(ownerFileName + owner + string(randMacKey) + fmt.Sprint(lastnodedata.NodeNum)))[:16])
	if newLastErr != nil {
		return newLastErr
	}

	// Set UUID of new node to the file's last node
	filedata.LastNodeUUID = newLastUUID

	//____________________________________________________________________________
	// Create new Content Node

	num := lastnodedata.NodeNum - 1
	conUUID, conUUIDErr := uuid.FromBytes(userlib.Hash([]byte(ownerFileName + owner + fmt.Sprint(num)))[:16])
	if conUUIDErr != nil {
		return conUUIDErr
	}

	// Prepare File Contents

	// Enc + Mac file contents
	encFile, macFile, errFile := EncryptAndMac(randConEnc, randConMac, userlib.RandomBytes(16), content)
	if errFile != nil {
		return errFile
	}
	// Wrap file contents
	wrapFile, wrapErr := WrapCipher(encFile, macFile)
	if wrapErr != nil {
		return wrapErr
	}

	//____________________________________________________________________________
	// Create new Node Struct (2nd to last node)

	var newnode Node
	newnode.CurrNodeUUID = conUUID
	newnode.NextNodeUUID = newLastUUID
	newnode.NodeNum = lastnodedata.NodeNum - 1

	//____________________________________________________________________________
	// Wrap Structs

	// File Struct
	marFile, errMarFile := json.Marshal(filedata)
	if errMarFile != nil {
		return errMarFile
	}
	encMarFile, macMarFile, errEncFile := EncryptAndMac(randEncKey, randMacKey, userlib.RandomBytes(16), marFile)
	if errEncFile != nil {
		return errEncFile
	}
	wrapMarFile, errWrapFile := WrapCipher(encMarFile, macMarFile)
	if errWrapFile != nil {
		return errWrapFile
	}

	// Empty Struct (last node)
	marNode, errMarNode := json.Marshal(lastnodedata)
	if errMarNode != nil {
		return errMarNode
	}
	encMarNode, macMarNode, errEncNode := EncryptAndMac(randEncKey, randMacKey, userlib.RandomBytes(16), marNode)
	if errEncNode != nil {
		return errEncNode
	}
	wrapMarNode, errWrapNode := WrapCipher(encMarNode, macMarNode)
	if errWrapNode != nil {
		return errWrapNode
	}

	// New Content Node (2nd to last node)
	marNodeNew, errMarNodeNew := json.Marshal(newnode)
	if errMarNodeNew != nil {
		return errMarNodeNew
	}
	encMarNodeNew, macMarNodeNew, errEncNodeNew := EncryptAndMac(randEncKey, randMacKey, userlib.RandomBytes(16), marNodeNew)
	if errEncNodeNew != nil {
		return errEncNodeNew
	}
	wrapMarNodeNew, errWrapNodeNew := WrapCipher(encMarNodeNew, macMarNodeNew)
	if errWrapNodeNew != nil {
		return errWrapNodeNew
	}

	//____________________________________________________________________________
	// Set and Store in Datastore

	// Rewrite updated File Struct
	userlib.DatastoreSet(fileUUID, wrapMarFile)

	// Overwrite empty node w/ new appended node
	userlib.DatastoreSet(lastNodeUUID, wrapMarNodeNew)

	// Store appended content in datastore
	userlib.DatastoreSet(conUUID, wrapFile)

	// Store new last empty node
	userlib.DatastoreSet(newLastUUID, wrapMarNode)

	return nil

}

// COMPLETE
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//____________________________________________________________________________
	// Create Keys

	//____________________________________________________________________________
	// Get Metadata Key

	// Create metadata key UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return nil, metaKeyErr
	}

	metaKey, ok0 := userlib.DatastoreGet(metaKeyUUID)
	if !ok0 {
		return nil, errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata key
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	unwrapKey, unwrapKeyErr := UnwrapCipher(metaKey)
	if unwrapKeyErr != nil {
		return nil, unwrapKeyErr
	}
	decKey, decKeyErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapKey.Ciphertext, unwrapKey.Mac_Sign)
	if decKeyErr != nil {
		return nil, decKeyErr
	}
	var metaKeydata MetadataKey
	unmarKeyErr := json.Unmarshal(decKey, &metaKeydata)
	if unmarKeyErr != nil {
		return nil, unmarKeyErr
	}

	metaUUID := metaKeydata.MetaUUID

	//____________________________________________________________________________
	// Get Metadata and Dec Keys

	wrapMeta, ok1 := userlib.DatastoreGet(metaUUID)
	if !ok1 {
		return nil, errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata
	unwrapMeta, unwrapMetaErr := UnwrapCipher(wrapMeta)
	if unwrapMetaErr != nil {
		return nil, unwrapMetaErr
	}
	decMeta, decMetaErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapMeta.Ciphertext, unwrapMeta.Mac_Sign)
	if decMetaErr != nil {
		return nil, decMetaErr
	}
	var metadata Metadata
	unmarMetaErr := json.Unmarshal(decMeta, &metadata)
	if unmarMetaErr != nil {
		return nil, unmarMetaErr
	}

	// Get rand keys
	ownerFileName := metadata.OriginalFilename
	owner := metadata.FileOwner
	randConEnc := metadata.ConDecKey
	randConMac := metadata.ConMacKey
	randEncKey := metadata.StrDecKey
	randMacKey := metadata.StrMacKey

	//____________________________________________________________________________
	// Create File UUID and get File

	fileUUID, fileErr := uuid.FromBytes(userlib.Hash([]byte(ownerFileName + owner + string(randEncKey)))[:16])
	if fileErr != nil {
		return nil, fileErr
	}

	wrapFile, ok8 := userlib.DatastoreGet(fileUUID)
	if !ok8 {
		return nil, errors.New(strings.ToTitle("Filename is incorrect"))
	}

	//____________________________________________________________________________
	// Get raw file struct

	unwrapFile, unwrapErr := UnwrapCipher(wrapFile)
	if unwrapErr != nil {
		return nil, unwrapErr
	}

	decFile, decErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrapFile.Ciphertext, unwrapFile.Mac_Sign)
	if decErr != nil {
		return nil, decErr
	}

	var filedata File

	unmarErr := json.Unmarshal(decFile, &filedata)
	if unmarErr != nil {
		return nil, unmarErr
	}

	lastCheck := filedata.LastNodeUUID

	//____________________________________________________________________________
	// Create Node UUID and get Node Struct

	nodeUUID, nodeErr := uuid.FromBytes(userlib.Hash([]byte(ownerFileName + owner + string(randMacKey)))[:16])
	if nodeErr != nil {
		return nil, nodeErr
	}

	wrapNode, ok := userlib.DatastoreGet(nodeUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("Filename does not exist"))
	}

	unwrap, unwrapErr := UnwrapCipher(wrapNode)
	if unwrapErr != nil {
		return nil, unwrapErr
	}

	dec, decErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrap.Ciphertext, unwrap.Mac_Sign)
	if decErr != nil {
		return nil, decErr
	}

	var firstnode Node

	unmarFirstErr := json.Unmarshal(dec, &firstnode)
	if unmarFirstErr != nil {
		return nil, unmarFirstErr
	}

	//____________________________________________________________________________
	// Loop through nodes

	// Get First Node contents
	// Unwrap the node's content
	firstCon, ok2 := userlib.DatastoreGet(firstnode.CurrNodeUUID)
	if !ok2 {
		return nil, errors.New(strings.ToTitle("Cannot retrieve contents"))
	}
	unFirst, unFirstErr := UnwrapCipher(firstCon)
	if unFirstErr != nil {
		return nil, unFirstErr
	}
	decFirst, decFirstErr := CheckMacAndDecrypt(randConEnc, randConMac, unFirst.Ciphertext, unFirst.Mac_Sign)
	if decFirstErr != nil {
		return nil, decFirstErr
	}

	// Initialize variables
	contents := string(decFirst)
	nextUUID := firstnode.NextNodeUUID

	for {
		check := nextUUID == lastCheck
		if check {
			break
		}

		// Unwrapping the Next Node
		wrapNext, ok3 := userlib.DatastoreGet(nextUUID)
		if !ok3 {
			return nil, errors.New(strings.ToTitle("Cannot retrieve next node"))
		}
		unwrapNext, unwrapNextErr := UnwrapCipher(wrapNext)
		if unwrapNextErr != nil {
			return nil, unwrapNextErr
		}
		decNext, decNextErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrapNext.Ciphertext, unwrapNext.Mac_Sign)
		if decNextErr != nil {
			return nil, decNextErr
		}
		var nextnode Node
		unmarNextErr := json.Unmarshal(decNext, &nextnode)
		if unmarNextErr != nil {
			return nil, unmarNextErr
		}

		// Unwrap the node's content
		wrapCon, ok4 := userlib.DatastoreGet(nextnode.CurrNodeUUID)
		if !ok4 {
			return nil, errors.New(strings.ToTitle("Cannot retrieve contents 2"))
		}
		unwrapCon, unwrapConErr := UnwrapCipher(wrapCon)
		if unwrapConErr != nil {
			return nil, unwrapConErr
		}
		decCon, decConErr := CheckMacAndDecrypt(randConEnc, randConMac, unwrapCon.Ciphertext, unwrapCon.Mac_Sign)
		if decConErr != nil {
			return nil, decConErr
		}

		contents = contents + string(decCon)
		nextUUID = nextnode.NextNodeUUID
	}

	result := []byte(contents)

	return result, nil

}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//____________________________________________________________________________
	// Create Keys

	// Check if recipient exists
	recPubKey, okUser := userlib.KeystoreGet(recipientUsername)
	if !okUser {
		return uuid.Nil, errors.New(strings.ToTitle("User does not exist"))
	}

	//____________________________________________________________________________
	// Get Metadata Key

	// Create metadata key UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return uuid.Nil, metaKeyErr
	}

	metaKey, ok0 := userlib.DatastoreGet(metaKeyUUID)
	if !ok0 {
		return uuid.Nil, errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata key
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	unwrapKey, unwrapKeyErr := UnwrapCipher(metaKey)
	if unwrapKeyErr != nil {
		return uuid.Nil, unwrapKeyErr
	}
	decKey, decKeyErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapKey.Ciphertext, unwrapKey.Mac_Sign)
	if decKeyErr != nil {
		return uuid.Nil, decKeyErr
	}
	var metaKeydata MetadataKey
	unmarKeyErr := json.Unmarshal(decKey, &metaKeydata)
	if unmarKeyErr != nil {
		return uuid.Nil, unmarKeyErr
	}

	metaUUID := metaKeydata.MetaUUID

	//____________________________________________________________________________
	// Get Metadata and Dec Keys

	wrapMeta, ok1 := userlib.DatastoreGet(metaUUID)
	if !ok1 {
		return uuid.Nil, errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata
	unwrapMeta, unwrapMetaErr := UnwrapCipher(wrapMeta)
	if unwrapMetaErr != nil {
		return uuid.Nil, unwrapMetaErr
	}
	decMeta, decMetaErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapMeta.Ciphertext, unwrapMeta.Mac_Sign)
	if decMetaErr != nil {
		return uuid.Nil, decMetaErr
	}
	var metadata Metadata
	unmarMetaErr := json.Unmarshal(decMeta, &metadata)
	if unmarMetaErr != nil {
		return uuid.Nil, unmarMetaErr
	}

	// Get rand keys
	owner := metadata.FileOwner
	randEncKey := metadata.StrDecKey
	randMacKey := metadata.StrMacKey

	//____________________________________________________________________________
	// Create File, Cipher UUID and get File

	fileUUID, fileErr := uuid.FromBytes(userlib.Hash([]byte(metadata.OriginalFilename + metadata.FileOwner + string(randEncKey)))[:16])
	if fileErr != nil {
		return uuid.Nil, fileErr
	}

	cipherUUID, cipherErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + recipientUsername))[:16])
	if cipherErr != nil {
		return uuid.Nil, cipherErr
	}

	file, ok2 := userlib.DatastoreGet(fileUUID)
	if !ok2 {
		return uuid.Nil, errors.New(strings.ToTitle("Filename is incorrect"))
	}

	//____________________________________________________________________________
	// Get raw file struct

	unwrapFile, unwrapErr := UnwrapCipher(file)
	if unwrapErr != nil {
		return uuid.Nil, unwrapErr
	}

	decFile, decErr := CheckMacAndDecrypt(randEncKey, randMacKey, unwrapFile.Ciphertext, unwrapFile.Mac_Sign)
	if decErr != nil {
		return uuid.Nil, decErr
	}

	var filedata File

	unmarErr := json.Unmarshal(decFile, &filedata)
	if unmarErr != nil {
		return uuid.Nil, unmarErr
	}

	filedata.UsersWAccess[recipientUsername] = filename
	ownercheck := userdata.Username == owner
	if !ownercheck {
		filedata.UsersNotAddedByOwner[recipientUsername] = userdata.Username
	}
	fmt.Println(filedata.UsersWAccess)

	//____________________________________________________________________________
	// Wrap File Struct

	marFile, errMarFile := json.Marshal(filedata)
	if errMarFile != nil {
		return uuid.Nil, errMarFile
	}
	encMarFile, macMarFile, errEncFile := EncryptAndMac(randEncKey, randMacKey, userlib.RandomBytes(16), marFile)
	if errEncFile != nil {
		return uuid.Nil, errEncFile
	}
	wrapMarFile, errWrapFile := WrapCipher(encMarFile, macMarFile)
	if errWrapFile != nil {
		return uuid.Nil, errWrapFile
	}

	//____________________________________________________________________________
	// Encrypt & Sign Metadata Key File

	encMeta, encMetaErr := userlib.PKEEnc(recPubKey, decKey)
	if encMetaErr != nil {
		return uuid.Nil, encMetaErr
	}

	signMeta, signErr := userlib.DSSign(userdata.DSPrivateKey, encMeta)
	if signErr != nil {
		return uuid.Nil, signErr
	}

	var cipher Ciphertext
	cipher.Ciphertext = encMeta
	cipher.Mac_Sign = signMeta

	marCipher, marErr := json.Marshal(cipher)
	if marErr != nil {
		return uuid.Nil, marErr
	}

	userlib.DatastoreSet(fileUUID, wrapMarFile)

	userlib.DatastoreSet(cipherUUID, marCipher)

	return cipherUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	//____________________________________________________________________________
	// Create temp keys

	//____________________________________________________________________________
	// Get ciphertext

	marCipher, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("Invalid invitation"))
	}

	var cipher Ciphertext

	unmarErr := json.Unmarshal(marCipher, &cipher)
	if unmarErr != nil {
		return unmarErr
	}

	// Generate salt
	salt := userlib.Hash([]byte(senderUsername))

	pubUUID := senderUsername + string(salt)

	sendDSPubKey, ok2 := userlib.KeystoreGet(pubUUID)
	if !ok2 {
		return errors.New(strings.ToTitle("Invalid sender"))
	}

	verErr := userlib.DSVerify(sendDSPubKey, cipher.Ciphertext, cipher.Mac_Sign)
	if verErr != nil {
		return verErr
	}

	decCipher, decErr := userlib.PKEDec(userdata.PKEPrivateKey, cipher.Ciphertext)
	if decErr != nil {
		return decErr
	}

	var metaKey MetadataKey
	unMetaErr := json.Unmarshal(decCipher, &metaKey)
	if unMetaErr != nil {
		return unMetaErr
	}

	MetaUUID := metaKey.MetaUUID

	//____________________________________________________________________________
	// Get metadata

	marMeta, ok3 := userlib.DatastoreGet(MetaUUID)
	if !ok3 {
		return errors.New(strings.ToTitle("Incorrect pointer sent 1"))
	}

	// Get raw metadata
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	unwrapMeta, unwrapMetaErr := UnwrapCipher(marMeta)
	if unwrapMetaErr != nil {
		return unwrapMetaErr
	}
	decMeta, decMetaErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapMeta.Ciphertext, unwrapMeta.Mac_Sign)
	if decMetaErr != nil {
		return decMetaErr
	}
	var metadata Metadata
	unmarMetaErr := json.Unmarshal(decMeta, &metadata)
	if unmarMetaErr != nil {
		return unmarMetaErr
	}

	// Get rand keys
	owner := metadata.FileOwner
	sendFileUUID := metadata.FileUUID
	randEncKey := metadata.StrDecKey
	randMacKey := metadata.StrMacKey

	// Get file struct

	//____________________________________________________________________________
	// Get file struct sender

	marSendFile, ok4 := userlib.DatastoreGet(sendFileUUID)
	if !ok4 {
		return errors.New(strings.ToTitle("Incorrect pointer sent 3"))
	}
	unSendFile, unSendFileErr := UnwrapCipher(marSendFile)
	if unSendFileErr != nil {
		return unSendFileErr
	}
	decSendFile, decSendFileErr := CheckMacAndDecrypt(randEncKey, randMacKey, unSendFile.Ciphertext, unSendFile.Mac_Sign)
	if decSendFileErr != nil {
		return decSendFileErr
	}
	var sendfile File
	sendErr := json.Unmarshal(decSendFile, &sendfile)
	if sendErr != nil {
		return errors.New(strings.ToTitle("Incorrect pointer sent 4"))
	}

	// Check to see if still in users with access
	userMap := sendfile.UsersWAccess
	_, okMap := userMap[userdata.Username]
	if !okMap {
		return errors.New(strings.ToTitle("Not an authorized user"))
	}

	// Set new filename of user with access
	userMap[userdata.Username] = filename
	checkowner := senderUsername == owner
	if !checkowner {
		sendfile.UsersNotAddedByOwner[userdata.Username] = senderUsername
	}
	sendfile.UsersWAccess = userMap

	//____________________________________________________________________________
	// Wrap sent file
	marFile, errMarFile := json.Marshal(sendfile)
	if errMarFile != nil {
		return errMarFile
	}
	encMarFile, macMarFile, errEncFile := EncryptAndMac(randEncKey, randMacKey, userlib.RandomBytes(16), marFile)
	if errEncFile != nil {
		return errEncFile
	}
	wrapMarFile, errWrapFile := WrapCipher(encMarFile, macMarFile)
	if errWrapFile != nil {
		return errWrapFile
	}

	//____________________________________________________________________________
	// Create new structs

	// MetaKey Struct
	var ownMetaKey MetadataKey
	ownMetaKey.MetaUUID = metaKey.MetaUUID

	//____________________________________________________________________________
	// Prepare structs

	// Marshal, Encrypt, Mac, and Wrap MetadataKey Struct
	marMetaKey, marMetaKeyErr := json.Marshal(ownMetaKey)
	if marMetaKeyErr != nil {
		return marMetaKeyErr
	}
	encMetaKey, macMetaKey, errMetaKey := EncryptAndMac(metaEncKey, metaMacKey, userlib.RandomBytes(16), marMetaKey)
	if errMetaKey != nil {
		return errMetaKey
	}
	wrapMetaKey, wrapMetaKeyErr := WrapCipher(encMetaKey, macMetaKey)
	if wrapMetaKeyErr != nil {
		return wrapMetaKeyErr
	}

	//____________________________________________________________________________
	// Store structs in Datastore

	// Create metadata UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return metaKeyErr
	}

	// Set metakey struct
	userlib.DatastoreSet(metaKeyUUID, wrapMetaKey)

	// Overwrite file struct
	userlib.DatastoreSet(sendFileUUID, wrapMarFile)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	// ____________________________________________________________________
	// Store Metadata on User's Personal List of Files

	//Remove Bob from the list of users of the shared file.

	//ReEncrypt the file using new key, and update the key for authorized users

	//Generate new encryption/decryption key for the file sharing => use a new salt + private key

	//HashKDF(Hash(priv key)||Salt) + Mac + Sign

	//Delete metadata file

	//regenpassword
	//rencrypt
	//redecrypt
	//readdress list of users

	//____________________________________________________________________________
	// Get Metadata Key Struct

	// Create metadata key UUID
	passHash := userlib.Hash([]byte("metadatakey"))

	metaKeyUUID, metaKeyErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(passHash)))[:16])
	if metaKeyErr != nil {
		return metaKeyErr
	}

	metaKey, ok0 := userlib.DatastoreGet(metaKeyUUID)
	if !ok0 {
		return errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata key
	metadataKey := userlib.Hash([]byte("metaKey"))
	metaEncKey := metadataKey[:16]
	metaMacKey := metadataKey[16:32]

	unwrapKey, unwrapKeyErr := UnwrapCipher(metaKey)
	if unwrapKeyErr != nil {
		return unwrapKeyErr
	}
	decKey, decKeyErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapKey.Ciphertext, unwrapKey.Mac_Sign)
	if decKeyErr != nil {
		return decKeyErr
	}
	var metaKeydata MetadataKey
	unmarKeyErr := json.Unmarshal(decKey, &metaKeydata)
	if unmarKeyErr != nil {
		return unmarKeyErr
	}

	metaUUID := metaKeydata.MetaUUID

	//____________________________________________________________________________
	// Get Metadata and Dec Keys

	wrapMeta, ok1 := userlib.DatastoreGet(metaUUID)
	if !ok1 {
		return errors.New(strings.ToTitle("Invalid request"))
	}

	// Get raw metadata
	unwrapMeta, unwrapMetaErr := UnwrapCipher(wrapMeta)
	if unwrapMetaErr != nil {
		return unwrapMetaErr
	}
	decMeta, decMetaErr := CheckMacAndDecrypt(metaEncKey, metaMacKey, unwrapMeta.Ciphertext, unwrapMeta.Mac_Sign)
	if decMetaErr != nil {
		return decMetaErr
	}
	var metadata Metadata
	unmarMetaErr := json.Unmarshal(decMeta, &metadata)
	if unmarMetaErr != nil {
		return unmarMetaErr
	}

	fileUUID := metadata.FileUUID

	//____________________________________________________________________________
	// Get File Struct

	wrapFile, ok2 := userlib.DatastoreGet(fileUUID)
	if !ok2 {
		return errors.New(strings.ToTitle("Filename is incorrect"))
	}

	unwrapFile, unwrapErr := UnwrapCipher(wrapFile)
	if unwrapErr != nil {
		return unwrapErr
	}

	decFile, decErr := CheckMacAndDecrypt(metadata.StrDecKey, metadata.StrMacKey, unwrapFile.Ciphertext, unwrapFile.Mac_Sign)
	if decErr != nil {
		return decErr
	}

	var filedata File

	unmarErr := json.Unmarshal(decFile, &filedata)
	if unmarErr != nil {
		return unmarErr
	}

	// check if user in map
	userMap := filedata.UsersWAccess
	_, okMap := userMap[recipientUsername]
	if !okMap {
		return errors.New(strings.ToTitle("Not an authorized user"))
	} else {
		revokeFilename := userMap[recipientUsername]
		revokeKeyUUID, revokeKeyErr := uuid.FromBytes(userlib.Hash([]byte(revokeFilename + recipientUsername + string(passHash)))[:16])
		if revokeKeyErr != nil {
			return revokeKeyErr
		}
		userlib.DatastoreDelete(revokeKeyUUID)
		delete(userMap, recipientUsername)
	}

	// check for users added by recipient
	addedMap := filedata.UsersNotAddedByOwner
	for recipient, sender := range addedMap {
		checksender := sender == recipientUsername
		if checksender {
			branchRevokeFilename := userMap[recipient]
			branchKeyUUID, branchKeyErr := uuid.FromBytes(userlib.Hash([]byte(branchRevokeFilename + recipient + string(passHash)))[:16])
			if branchKeyErr != nil {
				return branchKeyErr
			}
			userlib.DatastoreDelete(branchKeyUUID)
			delete(addedMap, recipient)
			delete(userMap, recipient)
		}
	}

	// update file struct
	filedata.UsersWAccess = userMap
	filedata.UsersNotAddedByOwner = addedMap

	// remove from datastore
	userlib.DatastoreDelete(fileUUID)

	//____________________________________________________________________________
	// Generate new keys

	rand := userlib.RandomBytes(64)
	conDecKey := rand[:16]
	conMacKey := rand[16:32]
	strDecKey := rand[32:48]
	strMacKey := rand[48:64]

	//____________________________________________________________________________
	// Get all new UUIDS

	// new FileUUID
	newFileUUID, newFileErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strDecKey)))[:16])
	if newFileErr != nil {
		return newFileErr
	}

	// new MetaUUID
	newMetaUUID := uuid.New()

	//____________________________________________________________________________
	// Get all old UUIDS

	// old MetaUUID
	// oldMetaUUID := metaKeydata.MetaUUID

	lastNode := filedata.LastNodeUUID
	currNode := filedata.FirstNodeUUID
	mapOfNodes := make(map[uuid.UUID][]byte)

	for {
		check := currNode == lastNode
		if check {
			// Unwrap empty Node
			wrapEmpNode, okEmp := userlib.DatastoreGet(currNode)
			if !okEmp {
				return errors.New(strings.ToTitle("Empty node error"))
			}
			unwrapEmp, unwrapEmpErr := UnwrapCipher(wrapEmpNode)
			if unwrapEmpErr != nil {
				return unwrapEmpErr
			}
			decEmp, decEmpErr := CheckMacAndDecrypt(metadata.StrDecKey, metadata.StrMacKey, unwrapEmp.Ciphertext, unwrapEmp.Mac_Sign)
			if decEmpErr != nil {
				return decEmpErr
			}
			var empNode Node
			unmarEmpErr := json.Unmarshal(decEmp, &empNode)
			if unmarEmpErr != nil {
				return unmarEmpErr
			}

			// Delete old empty node
			empnodeUUID, empnodeErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(metadata.StrMacKey) + fmt.Sprint(empNode.NodeNum)))[:16])
			if empnodeErr != nil {
				return empnodeErr
			}
			userlib.DatastoreDelete(empnodeUUID)

			// Rewrap empty node
			marNodeEmp, errMarNodeEmp := json.Marshal(empNode)
			if errMarNodeEmp != nil {
				return errMarNodeEmp
			}
			encMarNodeEmp, macMarNodeEmp, errEncNodeEmp := EncryptAndMac(strDecKey, strMacKey, userlib.RandomBytes(16), marNodeEmp)
			if errEncNodeEmp != nil {
				return errEncNodeEmp
			}
			wrapMarNodeEmp, errWrapNodeEmp := WrapCipher(encMarNodeEmp, macMarNodeEmp)
			if errWrapNodeEmp != nil {
				return errWrapNodeEmp
			}

			// Re-encrypt empty node UUID and save
			newEmpUUID, newEmpUUIDErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey) + fmt.Sprint(empNode.NodeNum)))[:16])
			if newEmpUUIDErr != nil {
				return newEmpUUIDErr
			}
			filedata.LastNodeUUID = newEmpUUID

			mapOfNodes[newEmpUUID] = wrapMarNodeEmp

			break
		}

		// Unwrap currNode
		wrapNode, ok := userlib.DatastoreGet(currNode)
		if !ok {
			return errors.New(strings.ToTitle("Filename does not exist"))
		}
		unwrap, unwrapErr := UnwrapCipher(wrapNode)
		if unwrapErr != nil {
			return unwrapErr
		}
		dec, decErr := CheckMacAndDecrypt(metadata.StrDecKey, metadata.StrMacKey, unwrap.Ciphertext, unwrap.Mac_Sign)
		if decErr != nil {
			return decErr
		}
		var node Node
		unmarFirstErr := json.Unmarshal(dec, &node)
		if unmarFirstErr != nil {
			return unmarFirstErr
		}

		// Unwrap content from CurrUUID
		wrapContent, okCon := userlib.DatastoreGet(node.CurrNodeUUID)
		if !okCon {
			return errors.New(strings.ToTitle("content not found"))
		}

		encContent, encConErr := UnwrapCipher(wrapContent)
		if encConErr != nil {
			return encConErr
		}

		content, decConErr := CheckMacAndDecrypt(metadata.ConDecKey, metadata.ConMacKey, encContent.Ciphertext, encContent.Mac_Sign)
		if decConErr != nil {
			return decConErr
		}

		// Wrap content with new keys
		newEncCon, newEncMac, newEncErr := EncryptAndMac(conDecKey, conMacKey, userlib.RandomBytes(16), content)
		if newEncErr != nil {
			return newEncErr
		}

		newWrapCon, newWrapErr := WrapCipher(newEncCon, newEncMac)
		if newWrapErr != nil {
			return newWrapErr
		}

		// DatastoreSet(wrapped content)
		userlib.DatastoreSet(node.CurrNodeUUID, newWrapCon)

		// Delete all nodes
		firstcheck := node.NodeNum == 0
		if firstcheck {
			nodeUUID1, node1Err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(metadata.StrMacKey)))[:16])
			if node1Err != nil {
				return node1Err
			}
			userlib.DatastoreDelete(nodeUUID1)
		} else {
			nodeUUID2, node2Err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(metadata.StrMacKey) + fmt.Sprint(node.NodeNum)))[:16])
			if node2Err != nil {
				return node2Err
			}
			userlib.DatastoreDelete(nodeUUID2)
		}

		// Change next node
		newNextUUID, newNextErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey) + fmt.Sprint(node.NodeNum+1)))[:16])
		if newNextErr != nil {
			return newNextErr
		}
		node.NextNodeUUID = newNextUUID

		// Wrap currnode
		marNodeNew, errMarNodeNew := json.Marshal(node)
		if errMarNodeNew != nil {
			return errMarNodeNew
		}
		encMarNodeNew, macMarNodeNew, errEncNodeNew := EncryptAndMac(strDecKey, strMacKey, userlib.RandomBytes(16), marNodeNew)
		if errEncNodeNew != nil {
			return errEncNodeNew
		}
		wrapMarNodeNew, errWrapNodeNew := WrapCipher(encMarNodeNew, macMarNodeNew)
		if errWrapNodeNew != nil {
			return errWrapNodeNew
		}

		// Re-encrypt curr UUID and save to map
		if firstcheck {
			nodeUUID3, node3Err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey)))[:16])
			if node3Err != nil {
				return node3Err
			}
			filedata.FirstNodeUUID = nodeUUID3
			mapOfNodes[nodeUUID3] = wrapMarNodeNew
		} else {
			nodeUUID4, node4Err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(strMacKey) + fmt.Sprint(node.NodeNum)))[:16])
			if node4Err != nil {
				return node4Err
			}
			mapOfNodes[nodeUUID4] = wrapMarNodeNew
		}

		// Get old next node
		oldNextUUID, oldNextErr := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username + string(metadata.StrMacKey) + fmt.Sprint(node.NodeNum+1)))[:16])
		if oldNextErr != nil {
			return oldNextErr
		}

		currNode = oldNextUUID
	}

	// Go through map of nodes, and DatastoreSet(newUUID, wrapped node)
	for nodeUUID, wrappedNode := range mapOfNodes {
		userlib.DatastoreSet(nodeUUID, wrappedNode)
	}

	// Change metadata content
	metadata.FileUUID = newFileUUID
	metadata.ConDecKey = conDecKey
	metadata.ConMacKey = conMacKey
	metadata.StrDecKey = strDecKey
	metadata.StrMacKey = strMacKey

	// Change metakey content
	metaKeydata.MetaUUID = newMetaUUID

	//____________________________________________________________________________
	//Rewrap metadata and metakey and file struct

	// metadata
	newMarMeta, mewMarMetaErr := json.Marshal(metadata)
	if mewMarMetaErr != nil {
		return mewMarMetaErr
	}
	newEncMeta, newMacMeta, newErrMeta := EncryptAndMac(metaEncKey, metaMacKey, userlib.RandomBytes(16), newMarMeta)
	if newErrMeta != nil {
		return newErrMeta
	}
	newWrapMeta, newWrapMetaErr := WrapCipher(newEncMeta, newMacMeta)
	if newWrapMetaErr != nil {
		return newWrapMetaErr
	}

	// metakey
	newMarKey, newMarKeyErr := json.Marshal(metaKeydata)
	if newMarKeyErr != nil {
		return newMarKeyErr
	}
	newEncKey, newMacKey, newErrKey := EncryptAndMac(metaEncKey, metaMacKey, userlib.RandomBytes(16), newMarKey)
	if newErrKey != nil {
		return newErrKey
	}
	newWrapKey, newWrapKeyErr := WrapCipher(newEncKey, newMacKey)
	if newWrapKeyErr != nil {
		return newWrapKeyErr
	}

	// File Struct
	newMarFile, newMarFileErr := json.Marshal(filedata)
	if newMarFileErr != nil {
		return newMarFileErr
	}
	newEncFile, newMacFile, errNewFile := EncryptAndMac(strDecKey, strMacKey, userlib.RandomBytes(16), newMarFile)
	if errNewFile != nil {
		return errNewFile
	}
	newWrapFile, newWrapFileErr := WrapCipher(newEncFile, newMacFile)
	if newWrapFileErr != nil {
		return newWrapFileErr
	}

	//____________________________________________________________________________
	// Delete and store the file, metadata

	// Delete old file struct
	userlib.DatastoreDelete(fileUUID)

	// Store new file struct
	userlib.DatastoreSet(newFileUUID, newWrapFile)

	// Delete old metadata
	userlib.DatastoreDelete(metaUUID)

	// Store new metadata
	userlib.DatastoreSet(newMetaUUID, newWrapMeta)

	// Overwrite the metakey for all users in usermap
	for user, userFile := range userMap {
		oldKeyUUID, oldKeyUUIDErr := uuid.FromBytes(userlib.Hash([]byte(userFile + user + string(passHash)))[:16])
		if oldKeyUUIDErr != nil {
			return oldKeyUUIDErr
		}

		// Overwrite metadata key
		userlib.DatastoreSet(oldKeyUUID, newWrapKey)

	}

	// Overwrite the metakey for yourself
	userlib.DatastoreSet(metaKeyUUID, newWrapKey)

	return nil
}

func WrapCipher(enc []byte, mac []byte) (cipherMarsh []byte, err error) {
	var cipher Ciphertext
	cipher.Ciphertext = enc
	cipher.Mac_Sign = mac

	// Marshal the info
	cipherRet, errcipherRet := json.Marshal(cipher)
	if errcipherRet != nil {
		return nil, errcipherRet
	}
	return cipherRet, nil

}
func UnwrapCipher(ciphertxt []byte) (cipherStructPtr *Ciphertext, err error) {
	var newCipher Ciphertext
	// unmarshal cipherfilelist
	errNewCipher := json.Unmarshal(ciphertxt, &newCipher)
	//userlib.DebugMsg("ciphertext : %v", ciphertxt)
	//userlib.DebugMsg("newCipher : %v", newCipher)
	if errNewCipher != nil {
		return nil, errNewCipher
	}
	return &newCipher, nil
}

func EncryptAndMac(keyEnc []byte, keyMac []byte, iv []byte, content []byte) (enc []byte, mac []byte, err error) {
	// symmetric encrypt file content
	encContent := userlib.SymEnc(keyEnc, iv, content)

	// maccontent
	macContent, macContErr := userlib.HMACEval(keyMac, encContent)
	if macContErr != nil {
		return nil, nil, macContErr
	}
	return encContent, macContent, nil
}

func CheckMacAndDecrypt(keyEnc []byte, keyMac []byte, cipher []byte, mac []byte) (dec []byte, err error) {
	reMac, errReMac := userlib.HMACEval(keyMac, cipher)
	if errReMac != nil {
		return nil, errReMac
	}
	//userlib.DebugMsg("Cipher: %v", cipher)
	checkMac := userlib.HMACEqual(reMac, mac)
	//userlib.DebugMsg("checkMac: %v", checkMac)
	if !checkMac {
		return nil, errors.New(strings.ToTitle("Content has been changed"))
	}

	decr := userlib.SymDec(keyEnc, cipher)
	//userlib.DebugMsg("keyEnc: %v", keyEnc)
	//userlib.DebugMsg("cipher: %v", cipher)

	return decr, nil
}
