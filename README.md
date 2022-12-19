# Magnus

A lightweight fun encryption/decryption GO script for personal use. For now, it can only provide:

1.	AES-256-CBC symmetric encryption and decryption
2.	RSA-4096 generation of key pairs
3.	RSA-4096 asymmetric encryption and decryption of the AES-256 key, using public/private keys. 

## Usage

### Symmetric Encryption/Decryption

If you want to encrypt a message using AES-256-CBC mode, you need to call Magnus this way:

`go run magnus.go -f encryptMessage -m "The message you want to encrypt" -k The32byteslongkeytoencrypt`

Now, if you need to decrypt the message, you call Magnus this way: 

`go run magnus.go -f decryptMessage -c "The ciphertext" -k The32byteslongkeytoencrypt`


### RSA-4096 key pair generation

As we all know, if you want to share encrypted messages with somebody, you need to assure the confidentiality of the symmetric key. One way to do that is exchanging it in the most secure way. That is why Magnus offers a RSA-4096 Key pair generation for key exchange. You can easily ask for your RSA keys this way:

`go run magnus.go -f genRSAKeyPair`

This will create two X.509 certificates in your local machine: `private_key.pem` and `public_key.pem`

### RSA-4096 key exchange

Let's say you and your friend want to exchange secret messages using AES-256-CBC, but you don't trust any method to securely exchange the AES Key. Magnus offers a very manual but effective way to do this in just a couple of steps:

1. Both you and your friend generate your key pairs. 
2. You tell your friend to send you their RSA Public Key
3. You encrypt the AES Key with their RSA Public Key
4. You send your friend the encrypted AES Key
5. Your friend decrypt the AES Key with their RSA Private Key. 

### RSA-4096 encryption

You can encrypt any AES key with RSA this way :
`go run magnus.go -f RSAEncrypt -rsapub "public_key.pem" -k The32byteslongAESKey`

(Keep in mind, the public key should be your friend's in order for they to successfully decrypt it later).

### RSA-4096 decryption
You can decrypt an AES Key that has been previously RSA-4096 encrypted this way: 
`go run magnus.go -f RSADecrypt -rsapriv "private_key.pem" -e The32byteslongEncryptedAESKey`

### AES 256 bit key generation
Of course you can use your own key. But if creating your own key is too much, you can always use Magnus to pseudo-randomize one for you. 

`go run magnus.go -f genAESKey`