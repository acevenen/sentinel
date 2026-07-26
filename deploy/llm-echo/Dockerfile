FROM golang:1.23-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/llm-echo main.go

FROM scratch
COPY --from=build /out/llm-echo /llm-echo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/llm-echo"]
