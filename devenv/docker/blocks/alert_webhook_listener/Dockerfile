
FROM golang:1.22rc2-bookworm 
ADD main.go /
WORKDIR /
RUN go build -o main . 
EXPOSE 3010
ENTRYPOINT ["/main"]
