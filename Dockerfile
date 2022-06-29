FROM clux/muslrust:1.61.0 as builder

WORKDIR /cherrybomb

COPY . /cherrybomb/

# install rust dependencies
RUN cargo install --path .

# build release cli executable
RUN cargo build --release

# pass on cli file from builder as cherrybomb 
FROM debian
COPY --from=builder /cherrybomb/target/release/cherrybomb .
ENTRYPOINT ["/cherrybomb"]