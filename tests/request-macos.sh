#!/usr/bin/env bash

LOG=
LOG="neqo_transport=info,debug"
DEFAULT_HOST="host.docker.internal:7443"
HOST="${1:-${DEFAULT_HOST}}"
LOCAL_URLS=( "https://${HOST}/" "https://${HOST}/css/bootstrap.min.css" \
             "https://${HOST}/css/fontAwesome.css" "https://${HOST}/css/hero-slider.css" \
             "https://${HOST}/css/templatemo-main.css" "https://${HOST}/css/owl-carousel.css" \
             "https://${HOST}/js/vendor/modernizr-2.8.3-respond-1.4.2.min.js" \
             "https://${HOST}/img/1st-item.jpg" "https://${HOST}/img/2nd-item.jpg" \
             "https://${HOST}/img/3rd-item.jpg" "https://${HOST}/img/4th-item.jpg" \
             "https://${HOST}/img/5th-item.jpg" "https://${HOST}/img/6th-item.jpg" \
             "https://${HOST}/img/1st-tab.jpg" "https://${HOST}/img/2nd-tab.jpg" \
             "https://${HOST}/img/3rd-tab.jpg" "https://${HOST}/img/4th-tab.jpg" \
             "https://${HOST}/js/vendor/bootstrap.min.js" "https://${HOST}/js/plugins.js" \
             "https://${HOST}/js/main.js" "https://${HOST}/img/1st-section.jpg" \
             "https://${HOST}/img/2nd-section.jpg" "https://${HOST}/img/3rd-section.jpg" \
             "https://${HOST}/img/4th-section.jpg" "https://${HOST}/img/5th-section.jpg" \
             "https://${HOST}/fonts/fontawesome-webfont.woff2?v=4.7.0" "https://${HOST}/img/prev.png" \
             "https://${HOST}/img/next.png" "https://${HOST}/img/loading.gif" \
             "https://${HOST}/img/close.png" )

DUMMY_URLS_VANILLA=(  "https://${HOST}/img/2nd-big-item.jpg" \
                      "https://${HOST}/css/bootstrap.min.css" \
                      "https://${HOST}/img/3rd-item.jpg" \
                      "https://${HOST}/img/4th-item.jpg" \
                      "https://${HOST}/img/5th-item.jpg" )

DEPS="deps-sample.csv"

# export LD_LIBRARY_PATH="$PWD/../target/debug/build/neqo-crypto-044e50838ff4228a/out/dist/Debug/lib/"
SSLKEYLOGFILE=out.log RUST_LOG=${LOG} exec ../target/debug/neqo-client "${LOCAL_URLS[@]}" --dummy-urls "${DUMMY_URLS_VANILLA[@]}" 

# CSDEF_NO_SHAPING=1 SSLKEYLOGFILE=out.log RUST_LOG=neqo_transport=info,debug ../target/debug/neqo-client --url-dependencies-from urls/000.csv 
