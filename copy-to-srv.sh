#!/bin/sh
rsync -hav AdGuardHome root@srv.abpvn.com:/var/www/html/dns/AdGuardHome_dev
ssh root@srv.abpvn.com "./update-dns.sh"
rsync -hav AdGuardHome root@srv2.abpvn.com:/var/www/html/dns/AdGuardHome_dev
ssh root@srv2.abpvn.com "./update-dns.sh"