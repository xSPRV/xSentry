FROM golang:1.27-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /xSentry ./cmd/xSentry

FROM alpine:latest

RUN apk add --no-cache git

WORKDIR /src

COPY --from=builder /xSentry /usr/local/bin/xSentry

ENTRYPOINT ["xSentry"]
