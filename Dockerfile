FROM  --platform=${BUILDPLATFORM} golang:1.20 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum main.go ./

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /voter

FROM --platform=${TARGETPLATFORM} gcr.io/distroless/base-debian10

WORKDIR /app

COPY --from=build /voter /app/voter 

VOLUME /app/session
ENV SESSION_DIR /app/session

ENTRYPOINT ["/app/voter"]