FROM alpine:3.3

RUN apk -U add curl

RUN curl https://secure-static.ztat.net/ca/zalando-service-combined.ca > \
      /usr/share/ca-certificates/zalando-service-combined.crt
RUN update-ca-certificates

COPY entrypoint.sh /

COPY build/linux/skoap /skoap
COPY scm-source.json /scm-source.json

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/skoap"]
