# Keyhouse Data Plane

## Purpose
The Keyhouse Data Plane serves SDK traffic.

## Endpoints

### GetSecret

Fetches a secret string with a given alias.

### GetSecrets

Fetches all secrets under a given customer key alias, or all secrets authorized to the requesters identity.

### StoreSecret

Updates a secret string with a given alias to a given value. Keyhouse is not guaranteed to return the updated secret immediately after calling `StoreSecret`. 

### EncodeDataKey

Fetches a fresh data key for SDK encryption use for a specific customer key alias.

It returns an encrypted form of the key to store alongside the payload, and a raw encryption key to encrypt the data.

### DecodeDataKey

Requests Keyhouse to decrypt a specific encrypted data key, for use in SDK decryption.
