FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.* ./
RUN go mod download && apk add --no-cache gcc musl-dev

COPY challenge .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags='-s -w' -trimpath -o secure-sign .

FROM alpine

WORKDIR /app
COPY --from=builder /build/secure-sign .
COPY challenge/public ./public
COPY entrypoint.sh /

EXPOSE 7000

CMD ["sh", "/entrypoint.sh"]
