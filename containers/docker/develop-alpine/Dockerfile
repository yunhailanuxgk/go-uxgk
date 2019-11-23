FROM alpine:3.5

RUN \
  apk add --update go git make gcc musl-dev linux-headers ca-certificates && \
  git clone --depth 1 https://github.com/yunhailanuxgk/go-uxgk && \
  (cd UXGK && make geth) && \
  cp UXGK/build/bin/geth /geth && \
  apk del go git make gcc musl-dev linux-headers && \
  rm -rf /UXGK && rm -rf /var/cache/apk/*

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/geth"]
