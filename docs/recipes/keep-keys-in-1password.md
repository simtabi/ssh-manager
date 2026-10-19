# Keep keys in 1Password

Generate and rotate a profile's private keys inside a 1Password vault, so only
the public halves are ever on disk.

You need the [1Password CLI](https://developer.1password.com/docs/cli/get-started/)
(`op` 2.20 or later), signed in, and the SSH agent turned on in the 1Password
app (Settings > Developer > Use the SSH agent).

In the manifest, give the profile a store and a vault:

```jsonc
"simtabibot": {
  "category": "orgs",
  "key_store": "1password",
  "op_vault": "Simtabi",
  "hosts": [
    {"alias": "github-simtabi", "hostname": "github.com", "user": "git",
     "provider": "github", "token_env": "GH_TOKEN_SIMTABI",
     "key_name": "simtabibot_github-ed25519"}
  ]
}
```

```sh
sshmgr doctor          # op found, agent socket present
sshmgr reconcile       # creates the item, writes simtabibot_github-ed25519.pub
sshmgr validate        # the item exists and matches the .pub
```

The rendered host points ssh at the public key and the 1Password agent:

```
Host github-simtabi
    HostName github.com
    User git
    IdentityFile ~/.ssh/profiles/orgs/simtabibot/simtabibot_github-ed25519.pub
    IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    IdentitiesOnly yes
```

Rotate the same way as any key:

```sh
sshmgr rotate simtabibot_github-ed25519
```

The new key is created in the vault as `<key>.staged`, deployed and verified,
then takes the live title, with the old item kept as `<key>.old`. Items are
archived, never deleted.

## Moving an existing profile into 1Password

Set `key_store` and `op_vault` on the profile, then rotate each of its keys. The
rotation generates the replacement in the vault and archives the old key file
pair to `old/`. Until you rotate, `validate` fails the key, because ssh would ask
the 1Password agent for a key it does not hold.

Full reference: [Key stores](../configuration.md#key-stores).

---

[← Docs index](../../README.md#documentation)
