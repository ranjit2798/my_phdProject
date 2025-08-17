using Argon2

# Hash a password (defaults to Argon2id)
password = "ranjit@1983"
hash = Argon2.hash(password)
println("Hashed: ", hash)

# Verify the password against the hash
is_valid = Argon2.verify(hash, password)
println("Password valid? ", is_valid)
