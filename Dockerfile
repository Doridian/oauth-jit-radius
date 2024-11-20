FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.23-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache ca-certificates

ARG GIT_REVISION=dev

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN go build -ldflags="-s -w" -trimpath -o /oauth-jit-radius .

FROM scratch AS default

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder templates /templates
COPY --from=builder /oauth-jit-radius /oauth-jit-radius

ENTRYPOINT [ "/oauth-jit-radius" ]
