# signed_kmod_tools
tool(s) to examine signed kernel modules

```
$ go build readsigs.go

$ ./readsigs -kmod [kernel_mod] -cert [cert_public_key.der]

```

example, gfs2_double.ko has been signed twice, the outer signature with the `testkey` keypair  and the inner one with the Fedora kmod signing key:

```
$ go build readsigs.go
$ ./readsigs -kmod gfs2_double.ko -cert testkey_pub.der 
kmod: gfs2_double.ko
cert: testkey_pub.der
Signature 1:
  signature verified
        subject: CN=cp3.chrisprocter.co.uk,O=kube9
        serial: 140021739515945850553976687443445479312715656853
Signature 2:
  signature not verified

```

Note: for secureboot/kmod validation purposes the Linux kernel only looks at the outer signature (Signature 1), any inner sigs are ignored  (therefore this kmod will not load on linux machine with secureboot enabled unless testkey_pub.der hass been added to the MOK database)
