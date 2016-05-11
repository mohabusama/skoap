FROM scratch
COPY build/linux/skoap /skoap
COPY scm-source.json /scm-source.json
ENTRYPOINT ["/skoap"]
