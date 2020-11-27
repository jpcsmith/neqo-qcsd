## Build the vanilla template and docker image

```
git clone https://github.com/litespeedtech/ols-dockerfiles.git
cd ols-dockerfiles/template
bash build.sh -L 1.7.5 -P lsphp74
cd -

docker build -t vanilla-srv ./docker
```

And start with: `./start-vanilla.sh`

### Accessing Additional Domains

There are currently two domains hosted on the server:

 - vanilla.neqo-test.com
 - weather.neqo-test.com

Both are accessible via QUIC on ports 443 and 7443.
Note that **SNI is necessary** to access the different domains, and is mandatory to access any domain if hosted on a non-loopback interface.
For example, to access the domain hosted in the cloud, run `./request-vanilla weather.neqo-test.com`, with the appropriate DNS entry set in
`/etc/hosts`.
