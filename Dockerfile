FROM golang:latest AS builder

WORKDIR /usr/src/ldapin

COPY . .

RUN go build -a -tags netgo -installsuffix netgo -o /ldapin


FROM scratch

COPY --from=builder /ldapin /ldapin

ENTRYPOINT ["/ldapin"]
