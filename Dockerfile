FROM golang:1.16 AS build
ENV PROJECT containerSsh_authServer
WORKDIR /src/$PROJECT
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOBIN=/usr/local/bin/ go install -a -ldflags=-w

FROM alpine
ARG user=appuser \
  group=appuser \
  uid=1001 \
  gid=1001
RUN addgroup -g ${gid} ${group} && adduser -D -u ${uid}  ${user} -G ${group}
COPY /bin/entrypoint.sh /etc/entrypoint
COPY --from=build /usr/local/bin/authServer /bin/authServer
ENTRYPOINT [ "/etc/entrypoint" ]
