FROM golang:1.23 AS builder

WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /oauth-jit-radius -trimpath -ldflags '-s -w' .

FROM alpine AS compressor
RUN apk add --no-cache upx
COPY --from=builder /oauth-jit-radius /oauth-jit-radius
RUN upx -9 /oauth-jit-radius -o /oauth-jit-radius-compressed

FROM scratch AS default

COPY --from=builder /oauth-jit-radius /oauth-jit-radius
ENTRYPOINT [ "/oauth-jit-radius" ]

FROM scratch AS compressed

COPY --from=compressor /oauth-jit-radius-compressed /oauth-jit-radius
ENTRYPOINT [ "/oauth-jit-radius" ]
