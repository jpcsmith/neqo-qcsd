#!/usr/bin/env bash

LOG=
LOG="neqo_transport=debug,error"
HOST="localhost:7443"
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

SSLKEYLOGFILE=out.log RUST_LOG=${LOG} exec ../target/debug/neqo-client "${LOCAL_URLS[@]}"
