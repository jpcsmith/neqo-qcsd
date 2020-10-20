FROM litespeedtech/openlitespeed:1.7.5-lsphp74

RUN apt-get -q update && apt-get -q install -y unzip && rm -rf /var/lib/apt/lists/*

RUN wget -q https://www.free-css.com/assets/files/free-css-templates/download/page259/vanilla.zip \
        && unzip -qq vanilla.zip \
        && rm vanilla.zip \
        && mv templatemo_526_vanilla/* /var/www/vhosts/localhost/html/ \
        && rmdir templatemo_526_vanilla
