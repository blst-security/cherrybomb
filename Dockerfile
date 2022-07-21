FROM rust:latest as builder


RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev
RUN update-ca-certificates

# Create appuser
ENV USER=myip
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"


WORKDIR /cherrybomb

COPY . /cherrybomb/

# install rust dependencies
RUN cargo install --path .

# build release cli executable
RUN cargo build --target x86_64-unknown-linux-musl --release


####################################################################################################
## Final image
####################################################################################################
# pass on cli file from builder as cherrybomb 
FROM debian:stable-slim

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder /cherrybomb/target/x86_64-unknown-linux-musl/release/cherrybomb ./

COPY --from=builder /cherrybomb/swagger/ ./swagger

USER myip:myip

ENTRYPOINT ["/cherrybomb"]