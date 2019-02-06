## PGP keys of Gitian builders and Developers

The file `keys.txt` contains fingerprints of the public keys of Gitian builders
and active developers.

The associated keys are mainly used to sign git commits or the build results
of Gitian builds.

The most recent version of each pgp key can be found on most pgp key servers.

Fetch the latest version from the key server to see if any key was revoked in
the meantime.
To fetch the latest version of all pgp keys in your gpg homedir,

```sh
gpg --refresh-keys
```

To fetch keys of Gitian builders and active developers, feed the list of
fingerprints of the primary keys into gpg:

```sh
# Ubuntu keyserver
while read fingerprint keyholder_name; do gpg --keyserver hkp://keyserver.ubuntu.com --recv-keys ${fingerprint}; done < ./keys.txt
# Debian keyring
while read fingerprint keyholder_name; do gpg --keyserver hkp://keyring.debian.org --recv-keys ${fingerprint}; done < ./keys.txt
# MIT keyserver
while read fingerprint keyholder_name; do gpg --keyserver hkp://pgp.mit.edu--recv-keys ${fingerprint}; done < ./keys.txt
# SKS keyservers used by OpenPGP
while read fingerprint keyholder_name; do gpg --keyserver hkp://subset.pool.sks-keyservers.net --recv-keys ${fingerprint}; done < ./keys.txt
```

Add your key to the list if you provided Gitian signatures for two major or
minor releases of ION Core.
