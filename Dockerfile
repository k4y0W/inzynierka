FROM golang:1.24-alpine
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod tidy
COPY . .
EXPOSE 8080
CMD ["go", "run", "main.go"]
