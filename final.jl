using Random
include("e:/paper work/Julia_code/Argon2.jl")
using Argon2
using SHA
using Base64
using Crypto
import Pkg
Pkg.add("ArgTools")

const VERSION = 1
const AEAD_KEY_LEN = 32        # AES-256-GCM
const AESGCM_NONCE_LEN = 12
const EPK_LEN = 32             # X25519 public key size (raw bytes)
const PWD_SALT_DEFAULT_LEN = 16
const HKDF_SALT_LEN = 32

function derive_sym_key(ss_classical::Vector{UInt8}, ss_pqc::Vector{UInt8}, salt::Vector{UInt8}, info::Vector{UInt8}=b"HYBRID-AEAD-2025")
    hkdf = HKDF(SHA256(), salt, info)
    return hkdf(ss_classical * ss_pqc, AEAD_KEY_LEN)
end

function argon2id_kdf(password::Vector{UInt8}, salt::Union{Nothing,Vector{UInt8}}=nothing;
    time_cost::Int=2, memory_cost_kib::Int=64 * 1024,
    parallelism::Int=1, out_len::Int=32)
    if salt === nothing
        salt = rand(UInt8, PWD_SALT_DEFAULT_LEN)
    end
    derived = Argon2.hash(password, salt; time_cost, memory_cost_kib, parallelism, hash_len=out_len, type=:id)
    return derived, salt
end

function _require_len(name::String, b::Vector{UInt8}, n::Int)
    if length(b) != n
        throw(ArgumentError("$name must be $n bytes, got $(length(b))"))
    end
end

function _read_checked(buf::Vector{UInt8}, idx::Int, n::Int)
    if idx + n > length(buf)
        throw(ArgumentError("Envelope truncated or malformed"))
    end
    return buf[idx:idx+n-1], idx + n
end

function hybrid_encrypt(plaintext::Vector{UInt8}, recipient_x25519_pubbytes::Vector{UInt8},
    recipient_kyber_alg::String, recipient_kyber_pub::Vector{UInt8};
    sender_ed25519_sign_fn::Union{Nothing,Function}=nothing,
    password::Union{Nothing,Vector{UInt8}}=nothing,
    associated_data::Vector{UInt8}=b"")
    _require_len("recipient_x25519_pubbytes", recipient_x25519_pubbytes, EPK_LEN)

    flags = 0
    if sender_ed25519_sign_fn !== nothing
        flags |= 0x01
    end
    if password !== nothing
        flags |= 0x02
    end

    # 1) ephemeral X25519
    esk = rand(UInt8, EPK_LEN)  # Replace with actual X25519 key generation
    epk = esk  # Replace with actual public key derivation

    # 2) classical shared secret
    ss_classical = rand(UInt8, EPK_LEN)  # Replace with actual ECDH exchange

    # 3) PQC KEM (Kyber)
    kyber_ct = rand(UInt8, 32)  # Replace with actual Kyber ciphertext
    ss_pqc = rand(UInt8, 32)    # Replace with actual Kyber shared secret

    # 4) optional Argon2id from password
    pwd_secret = UInt8[]
    pwd_salt = UInt8[]
    if password !== nothing
        pwd_secret, pwd_salt = argon2id_kdf(password, nothing, out_len=32)
    end

    # 5) derive AEAD key via HKDF
    hkdf_salt = rand(UInt8, HKDF_SALT_LEN)
    key = derive_sym_key(ss_classical, ss_pqc * pwd_secret, hkdf_salt)

    # 6) AES-GCM encrypt
    nonce = rand(UInt8, AESGCM_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    # 7) optional signature
    signature = UInt8[]
    if sender_ed25519_sign_fn !== nothing
        to_sign = vcat(
            UInt8[VERSION],
            UInt8[flags],
            epk,
            UInt8(length(kyber_ct)),
            kyber_ct,
            UInt8(length(pwd_salt)),
            pwd_salt,
            UInt8(length(hkdf_salt)),
            hkdf_salt,
            UInt8(length(nonce)),
            nonce,
            UInt8(length(ciphertext)),
            ciphertext
        )
        signature = sender_ed25519_sign_fn(to_sign)
    end

    # 8) pack envelope
    envelope = UInt8[]
    push!(envelope, VERSION)
    push!(envelope, flags)
    append!(envelope, UInt8(length(kyber_ct)))
    append!(envelope, epk)
    append!(envelope, kyber_ct)

    if password !== nothing
        push!(envelope, UInt8(length(pwd_salt)))
        append!(envelope, pwd_salt)
    else
        push!(envelope, 0)
    end

    push!(envelope, UInt8(length(hkdf_salt)))
    append!(envelope, hkdf_salt)

    push!(envelope, UInt8(length(nonce)))
    append!(envelope, nonce)

    append!(envelope, UInt8(length(ciphertext)))
    append!(envelope, ciphertext)

    if !isempty(signature)
        append!(envelope, UInt8(length(signature)))
        append!(envelope, signature)
    end

    return envelope
end

# Example usage
plaintext = b"Hello, World!"
recipient_x25519_pubbytes = rand(UInt8, 32)  # Replace with actual public key
recipient_kyber_alg = "Kyber768"  # Example algorithm
recipient_kyber_pub = rand(UInt8, 32)  # Replace with actual public key

try
    encrypted_data = hybrid_encrypt(plaintext, recipient_x25519_pubbytes, recipient_kyber_alg, recipient_kyber_pub)
    println("Encrypted Data: ", encrypted_data)
catch e
    println("An error occurred: ", e)
end