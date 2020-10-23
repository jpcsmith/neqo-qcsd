## Run a simple HTML, js, Bootstrap-CSS website template on the Open Litespeed
## webserver for testing.
##
FROM litespeedtech/openlitespeed:1.7.5-lsphp74

RUN apt-get -q update && apt-get -q install -y unzip && rm -rf /var/lib/apt/lists/*

RUN wget -q https://www.free-css.com/assets/files/free-css-templates/download/page259/vanilla.zip \
        && unzip -qq vanilla.zip \
        && rm vanilla.zip \
        && mv templatemo_526_vanilla/* /var/www/vhosts/localhost/html/ \
        && rmdir templatemo_526_vanilla

# Use port 7443 for HTTPS
# RUN sed -i 's/:443/:7443/' /usr/local/lsws/conf/httpd_config.conf
COPY httpd_config.conf /usr/local/lsws/conf/httpd_config.conf

# The ports to be published are exposed below
# - Ports for HTTP connections
EXPOSE 80/tcp
EXPOSE 80/udp

# - Ports for HTTPS connections
EXPOSE 7443/tcp
EXPOSE 7443/udp

# - Ports for administration
EXPOSE 7080/tcp
EXPOSE 7080/udp
