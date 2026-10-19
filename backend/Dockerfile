FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dhaal .

FROM debian:bookworm-slim
# ffmpeg converts phone/browser audio (m4a, amr, webm, 3gp) into formats Gemini reads.
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /dhaal /dhaal
USER nobody
CMD ["/dhaal"]
