FROM golang:1.20 AS build

WORKDIR /app

COPY go.mod go.sum main.go ./

RUN go build -o /voter

FROM gcr.io/distroless/base-debian10

WORKDIR /app

COPY --from=build /voter /app/voter 

VOLUME /app/session
ENV SESSION_DIR /app/session

ENTRYPOINT ["/app/voter"]