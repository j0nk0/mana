
help:           ## Show this help.
        @fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//'

.git:           ## Git init/sync recurse submodules
        git init
	git submodule sync
	git submodule update --init --recursive --remote

python-reqs:    ## Install python packages in requirements.txt
        pip install --upgrade -r requirements.txt

CLEANUP = *.log

clean:          ## Remove shit .log files (see CLEANUP)
        rm -rf ${CLEANUP}

all:
        $(MAKE) -C hostapd-mana/hostapd/

install:
		##Install python packages in reuirements.txt
	python-reqs

		## Git init/sync recurse submodules
	.git

		## Create the target directories
	install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/nodogsplash
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/hostapd-2.6
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/crackpkcs8
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/apache
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/hostapd-2.3
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/MITMf
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/coinhive-js
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/hostapd-mana

        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/cert
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/www
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/crackapd
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/firelamb
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/sslstrip2
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/sslstrip2/sslstrip
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/sslstrip-hsts/dns2proxy
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/net-creds
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/cert
        install -d -m 755 $(DESTDIR)/usr/share/mana-toolkit/run-mana/conf
        install -d -m 755 $(DESTDIR)/usr/lib/mana-toolkit/
        install -d -m 755 $(DESTDIR)/var/lib/mana-toolkit/sslsplit
        install -d -m 755 $(DESTDIR)/etc/mana-toolkit/
        install -d -m 755 $(DESTDIR)/etc/apache2/sites-available/
                ## Install configuration files & Apache2 files
        install -m 644 * $(DESTDIR)/usr/share/mana-toolkit/
        install -m 644 apache/etc/apache2/sites-available/* $(DESTDIR)/etc/apache2/sites-available/
                ## Install the data
        cp -R apache/var/www/* $(DESTDIR)/usr/share/mana-toolkit/www/

                ## Dynamic configuration (if not fake install)
        if [ "$(DESTDIR)" = "" ]; then \
            a2enmod rewrite || true; \
            a2dissite 000-default || true; \
            for conf in apache/etc/apache2/sites-available/*; do \
                a2ensite `basename $$conf` || true; \
            done; \
        fi

