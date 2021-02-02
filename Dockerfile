FROM golang:latest AS builder

WORKDIR /usr/src/lauth

COPY . .

RUN go build -a -tags netgo -installsuffix netgo -o /lauth


FROM scratch

COPY --from=builder /lauth /lauth

ENTRYPOINT ["/lauth"]
