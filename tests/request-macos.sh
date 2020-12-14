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

# export LD_LIBRARY_PATH="$PWD/../target/debug/build/neqo-crypto-044e50838ff4228a/out/dist/Debug/lib/"
SSLKEYLOGFILE=out.log RUST_LOG=${LOG} exec ../target/debug/neqo-client "${LOCAL_URLS[@]}"

# SSLKEYLOGFILE=out.log RUST_LOG=${LOG} exec ./target/debug/neqo-client --output-dir html-output 'https://localhost/' 'https://localhost/css/bootstrap.min.css' 'https://localhost/css/fontAwesome.css' 'https://localhost/css/hero-slider.css' 'https://localhost/css/templatemo-main.css' 'https://localhost/css/owl-carousel.css' 'https://fonts.googleapis.com/css?family=Open+Sans:300 400 600 700 800' 'https://localhost/js/vendor/modernizr-2.8.3-respond-1.4.2.min.js' 'https://localhost/img/1st-item.jpg' 'https://localhost/img/2nd-item.jpg' 'https://localhost/img/3rd-item.jpg' 'https://localhost/img/4th-item.jpg' 'https://localhost/img/5th-item.jpg' 'https://localhost/img/6th-item.jpg' 'https://localhost/img/1st-tab.jpg' 'https://localhost/img/2nd-tab.jpg' 'https://localhost/img/3rd-tab.jpg' 'https://localhost/img/4th-tab.jpg' 'https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js' 'https://localhost/js/vendor/bootstrap.min.js' 'https://localhost/js/plugins.js' 'https://localhost/js/main.js' 'https://fonts.gstatic.com/s/opensans/v18/mem8YaGs126MiZpBA-UFVZ0b.woff2' 'https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d1197183.8373802372!2d-1.9415093691103689!3d6.781986417238027!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0xfdb96f349e85efd%3A0xb8d1e0b88af1f0f5!2sKumasi+Central+Market!5e0!3m2!1sen!2sth!4v1532967884907' 'https://localhost/img/1st-section.jpg' 'https://localhost/img/2nd-section.jpg' 'https://localhost/img/3rd-section.jpg' 'https://localhost/img/4th-section.jpg' 'https://localhost/img/5th-section.jpg' 'https://localhost/fonts/fontawesome-webfont.woff2?v=4.7.0' 'https://localhost/img/prev.png' 'https://localhost/img/next.png' 'https://localhost/img/loading.gif' 'https://localhost/img/close.png' 'https://maps.googleapis.com/maps/api/js?client=google-maps-embed&paint_origin=&libraries=geometry search&v=3.exp&language=en_GB&region=th&callback=onApiLoad' 'https://maps.gstatic.com/maps-api-v3/embed/js/42/8/intl/en_gb/init_embed.js' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/common.js' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/util.js' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/map.js' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/overlay.js' 'https://maps.gstatic.com/mapfiles/embed/images/google4_hdpi.png' 'https://maps.gstatic.com/mapfiles/openhand_8_8.cur' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/onion.js' 'https://maps.googleapis.com/maps/api/js/StaticMapService.GetMapImage?1m2&1i32328&2i31351&2e1&3u8&4m2&1u290&2u390&5m5&1e0&5sen-GB&6sth&10b1&12b1&client=google-maps-embed&token=21325' 'https://maps.googleapis.com/maps-api-v3/api/js/42/8/intl/en_gb/search_impl.js' 'https://maps.googleapis.com/maps/api/js/ViewportInfoService.GetViewportInfo?1m6&1m2&1d3.3453369140625&2d-4.141845703125&2m2&1d10.0360107421875&2d0.7965087890625&2u8&4sen-GB&5e0&6sm%40528000000&7b0&8e0&11e289&12e2&callback=_xdc_._5mki0h&client=google-maps-embed&token=95145' 'https://maps.googleapis.com/maps/api/js/ViewportInfoService.GetViewportInfo?1m6&1m2&1d4.146179898926263&2d-4.146179898926263&2m2&1d9.28744297359483&2d0.9950831757423031&2u5&4sen-GB&5e2&7b0&8e0&11e289&12e2&callback=_xdc_._7s5fe6&client=google-maps-embed&token=42348' 'https://maps.googleapis.com/maps/api/js/AuthenticationService.Authenticate?1shttps%3A%2F%2Fwww.google.com%2Fmaps%2Fembed%3Fpb%3D!1m18!1m12!1m3!1d1197183.8373802372!2d-1.9415093691103689!3d6.781986417238027!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0xfdb96f349e85efd%253A0xb8d1e0b88af1f0f5!2sKumasi%2BCentral%2BMarket!5e0!3m2!1sen!2sth!4v1532967884907&2sgoogle-maps-embed&callback=_xdc_._2aeh6e&client=google-maps-embed&token=70809'
