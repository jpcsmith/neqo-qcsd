## Build the vanilla template and docker image

```
git clone https://github.com/litespeedtech/ols-dockerfiles.git
cd ols-dockerfiles/template
bash build.sh -L 1.7.5 -P lsphp74
cd -

docker build -t vanilla-srv ./docker
```

And start with: `./start-vanilla.sh`
