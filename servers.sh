if [[ -z ${DIAMANEOS_SERVERS_FILE:-} || ! -f $DIAMANEOS_SERVERS_FILE ||
      ! -r $DIAMANEOS_SERVERS_FILE || ! -O $DIAMANEOS_SERVERS_FILE || -L $DIAMANEOS_SERVERS_FILE ]]; then
    echo 'Set DIAMANEOS_SERVERS_FILE to a current-user-owned deployment configuration.' >&2
    return 1
fi
if [[ -n $(find "$DIAMANEOS_SERVERS_FILE" \( -perm -020 -o -perm -002 \) -print) ]]; then
    echo "Private deployment manifests must not be writable by other users." >&2
    return 1
fi
. "$DIAMANEOS_SERVERS_FILE"
