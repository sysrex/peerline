FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build arguments for version info
# Empty defaults allow fallback to runtime/debug.ReadBuildInfo
ARG VERSION=
ARG COMMIT=
ARG SOURCE_COMMIT=
ARG BUILD_TIME=
ARG SOURCE_DATE_EPOCH=

# Validate build args (reject spaces, quotes, control characters)
# SOURCE_DATE_EPOCH must be digits only; others allow alphanumeric + ._+:-
RUN set -e; \
    for val in "$VERSION" "$COMMIT" "$SOURCE_COMMIT" "$BUILD_TIME"; do \
        case "$val" in \
            *[!A-Za-z0-9._+:-]*) \
                echo "ERROR: Invalid build arg contains forbidden characters" >&2; \
                exit 1; \
                ;; \
        esac; \
    done; \
    if [ -n "$SOURCE_DATE_EPOCH" ]; then \
        case "$SOURCE_DATE_EPOCH" in \
            *[!0-9]*) \
                echo "ERROR: SOURCE_DATE_EPOCH must be digits only" >&2; \
                exit 1; \
                ;; \
        esac; \
    fi

# Build with version info injected via ldflags
# Only pass -X flags for non-empty values to enable fallbacks
RUN set -e; \
    LDFLAGS="-s -w"; \
    [ -n "$VERSION" ] && LDFLAGS="$LDFLAGS -X github.com/sysrex/peerline/internal/version.Version=$VERSION"; \
    COMMIT_VAL="${COMMIT:-$SOURCE_COMMIT}"; \
    [ -n "$COMMIT_VAL" ] && LDFLAGS="$LDFLAGS -X github.com/sysrex/peerline/internal/version.Commit=$COMMIT_VAL"; \
    BUILD_TIME_VAL="$BUILD_TIME"; \
    [ -z "$BUILD_TIME_VAL" ] && [ -n "$SOURCE_DATE_EPOCH" ] && BUILD_TIME_VAL="$(date -u -d @$SOURCE_DATE_EPOCH +%Y-%m-%dT%H:%M:%SZ)"; \
    [ -n "$BUILD_TIME_VAL" ] && LDFLAGS="$LDFLAGS -X github.com/sysrex/peerline/internal/version.BuildTime=$BUILD_TIME_VAL"; \
    CGO_ENABLED=0 go build -trimpath -ldflags="$LDFLAGS" -o /peerline ./cmd/peerline

FROM gcr.io/distroless/static:nonroot
COPY --from=build /peerline /peerline
VOLUME /data
ENV PEERLINE_ADDR=0.0.0.0:8787 PEERLINE_DB=/data/peerline.db
EXPOSE 8787
ENTRYPOINT ["/peerline"]
