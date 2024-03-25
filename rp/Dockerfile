FROM golang:1.21

WORKDIR /app

COPY * ./
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /rp

EXPOSE 8001

CMD ["/rp"]