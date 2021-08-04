# Keyhouse Control Plane

## Purpose
The Keyhouse Data Plane serves administrator/operator traffic.

## Endpoints

### GET /info
Takes no arguments.
Currently it serves as an authentication check, responding hello <name>. 

### GET /keyrings
Gets information on all authorized keyrings.

Takes no arguments.

Returns a JSON body consisting of an array of Keyrings that the currently authenticated user is authorized to see.

### POST /keyrings
Creates a new keyring.

Must have header content-type: application/json.  Takes the following input format:
```rust
{
    "alias": String,
    "description": String,
    "level": "L2" | "L3" | "L4" // Corresponds to security level
}
```
For example:
```json
{
    "alias": "test key",
    "description": "used for testing",
    "level": "L3"
}
```

Returns a JSON body consisting of a single created Keyring that has been sucessfully created. If the alias is already in use, a 403 Forbidden error is returned. The only authorized owner of the new keyring will be the currently authenticated user.

### GET /keyrings/:keyring_alias
Gets information on a single keyring.

Takes 'keyring_alias' as a string based path argument.

Returns a JSON body consisting of a single Keyring that the currently authenticated user is authorized to see.

### GET /keyrings/:keyring_alias/customer_key
Lists all [Customer Key](encryption.md#customer-key) information under a keyring the user is authorized to see.

Takes 'keyring_alias' as a string based path argument.

Returns a JSON body consisting of an array of Customer Keys that the currently authenticated user is authorized to see.

### POST /keyrings/:keyring_alias/customer_key

Creates a new [Customer Key](encryption.md#customer-key) under a keyring that the currently authenticated user is authorized to see.

Must have header content-type: application/json.

Takes the following input format:
```rust
{
    "alias": String,
    "description": String,
    "purpose": "EncodeDecode" | "SignVerify" | "Secret",
    "acls": AccessControlLists
}
```

Returns a JSON body consisting of a single created [Customer Key](encryption.md#customer-key) that has been successfully created. If the alias is already in use, a 403 Forbidden error is returned.

### GET /keyrings/:keyring_alias/customer_key/:key_alias
Gets information on a single [Customer Key](encryption.md#customer-key).

Takes 'keyring_alias' and 'key_alias' as string based path arguments.

Returns a JSON body consisting of a single [Customer Key](encryption.md#customer-key) that the currently authenticated user is authorized to see.

### PATCH /keyrings/:keyring_alias/customer_key/:key_alias
Performs a partial update on a single customer key.

Takes 'keyring_alias' and 'key_alias' as string based path arguments.

Must have header content-type: application/json.

Takes the following input format:

Note here that a suffixing `?` denotes an optional/nullable field, if not present, the field is not updated in the underlying customer key

```rust
{
    "description": String?,
    "acls": AccessControlLists?,
    "status": ("Enabled" | "Disabled")? // can only change from enabled -> disabled
}
```

Returns a JSON body consisting of a single, post-mutation, [Customer Key](encryption.md#customer-key) that the currently authenticated user is authorized to see.

### GET /keyrings/:keyring_alias/customer_key/:key_alias/secret
Lists all [Secrets](encryption.md#secrets) under a customer key the user is authorized to see.

Takes 'keyring_alias' and 'key_alias' as string based path arguments.

Returns a JSON body consisting of an array of [Secrets](encryption.md#secrets) contained within the given customer key.

### POST /keyrings/:keyring_alias/customer_key/:key_alias/secret/:secret_alias
Creates or updates a new/existing [Secret](encryption.md#secrets) under a customer key.

Must have header content-type: application/json.

Takes the following input format:
```rust
{
    "secret": String?, // the new value the secret should have, doesn't change if not present. DOES CHANGE IF EMPTY
    "description": String?, // the new value of description, doesn't change if not present. DOES CHANGE IF EMPTY
}
```

Returns a JSON body consisting of the updated [Secret](encryption.md#secrets) that has been successfully created. Aliases for secrets are namespaced to their parent customer key.

### DELETE /keyrings/:keyring_alias/customer_key/:key_alias/secret/:secret_alias
Deletes existing [Secret](encryption.md#secrets) under a customer key.
