package main

# Do Not store secrets in ENV variables
secrets_env := [
    "passwd",
    "password",
    "pass",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
    "tkn"
]

deny[msg] {
    input[i].Cmd == "env"
    val := input[i].Value
    some j
    some k
    val[j] != ""
    secrets_env[k] != ""
    contains(lower(val[j]), secrets_env[k])
    msg := sprintf("Line %d: Potential secret in ENV key found: %s", [i, val[j]])
}

# Only use trusted base images (commented out for now)
# deny[msg] {
#     input[i].Cmd == "from"
#     val := split(input[i].Value[0], "/")
#     count(val) > 1
#     msg := sprintf("Line %d: use a trusted base image", [i])
# }

# Do not use 'latest' tag for base images
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    count(val) > 1
    contains(lower(val[1]), "latest")
    msg := sprintf("Line %d: do not use 'latest' tag for base images", [i])
}

# Avoid curl bashing
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    regex.find_n("(curl|wget)[^|>]*[|>]", lower(val), -1)[_]  # Match if at least one result
    msg := sprintf("Line %d: Avoid curl bashing", [i])
}

# Do not upgrade your system packages
warn[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    regex.match(".*?(apk|yum|dnf|apt|pip).+?(install|dist-|check-|group)?up(grade|date).*", lower(val))
    msg := sprintf("Line %d: Do not upgrade your system packages: %s", [i, val])
}

# Do not use ADD if possible
deny[msg] {
    input[i].Cmd == "add"
    msg := sprintf("Line %d: Use COPY instead of ADD", [i])
}

# Any user detection
any_user {
    input[i].Cmd == "user"
}

deny[msg] {
    not any_user
    msg := "Do not run as root, use USER instead"
}

# ... but do not use root
forbidden_users := [
    "root",
    "toor",
    "0"
]

deny[msg] {
    command := "user"
    users := [name | input[i].Cmd == "user"; name := input[i].Value[0]]
    lastuser := users[count(users)-1]
    some f
    contains(lower(lastuser), forbidden_users[f])
    msg := sprintf("Line %d: Last USER directive (USER %s) is forbidden", [i, lastuser])
}

# Do not sudo
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg := sprintf("Line %d: Do not use 'sudo' command", [i])
}

# Use multi-stage builds
default multi_stage = false

multi_stage {
    input[i].Cmd == "copy"
    val := concat(" ", input[i].Flags)
    contains(lower(val), "--from=")
}

deny[msg] {
    multi_stage == false
    msg := "You COPY, but do not appear to use multi-stage builds..."
}

