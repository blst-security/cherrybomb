# syntax=docker/dockerfile:1
FROM ubuntu:18.04
COPY ./target/x86_64-unknown-linux-gnu/release/cherrybomb /usr/local/bin
