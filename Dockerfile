FROM golang:1.23 AS builder

WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /foxRADIUS -trimpath -ldflags '-s -w' .

FROM alpine AS compressor
RUN apk add --no-cache upx
COPY --from=builder /foxRADIUS /foxRADIUS
RUN upx -9 /foxRADIUS -o /foxRADIUS-compressed

FROM scratch AS default

COPY --from=builder /foxRADIUS /foxRADIUS
ENTRYPOINT [ "/foxRADIUS" ]

FROM scratch AS compressed

COPY --from=compressor /foxRADIUS-compressed /foxRADIUS
ENTRYPOINT [ "/foxRADIUS" ]
