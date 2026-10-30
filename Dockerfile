FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /peerline ./cmd/peerline

FROM gcr.io/distroless/static:nonroot
COPY --from=build /peerline /peerline
VOLUME /data
ENV PEERLINE_ADDR=0.0.0.0:8787 PEERLINE_DB=/data/peerline.db
EXPOSE 8787
ENTRYPOINT ["/peerline"]
