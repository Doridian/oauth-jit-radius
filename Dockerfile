FROM golang:1.23 AS builder

WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /out/foxRADIUS -trimpath -ldflags '-s -w' .

FROM scratch

COPY --from=builder /out/foxRADIUS /foxRADIUS
ENTRYPOINT [ "/foxRADIUS" ]
