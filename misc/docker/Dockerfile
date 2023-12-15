FROM golang:1.20.2-bullseye as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .


FROM pihole/pihole:2023.03.1
RUN apt-get update && apt-get install -y iproute2
COPY --from=builder /app/main /
COPY --from=builder /app/config.ini /
CMD ["./main"]
