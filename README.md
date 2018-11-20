&nbsp;
<p align="center">
  <img src="https://cdn.adguard.com/public/Adguard/Common/adguard_home.svg" width="300px" alt="AdGuard Home" />
</p>
<h3 align="center">Privacy protection center for you and your devices</h3>
<p align="center">
  Free and open source, powerful network-wide ads & trackers blocking DNS server.
</p>

<p align="center">
    <a href="https://adguard.com/">AdGuard.com</a> |
    <a href="https://github.com/AdguardTeam/AdGuardHome/wiki">Wiki</a> |
    <a href="https://reddit.com/r/Adguard">Reddit</a> |
    <a href="https://twitter.com/AdGuard">Twitter</a>
    <br /><br />
    <a href="https://travis-ci.org/AdguardTeam/AdGuardHome">
      <img src="https://travis-ci.org/AdguardTeam/AdGuardHome.svg" alt="Build status" />
    </a>
    <a href="https://github.com/AdguardTeam/AdGuardHome/releases">
        <img src="https://img.shields.io/github/release/AdguardTeam/AdGuardHome/all.svg" alt="Latest release" />
    </a>
</p>

<br />

<p align="center">
    <img src="https://cdn.adguard.com/public/Adguard/Common/adguard_home.gif" width="800" />
</p>

<hr />

# AdGuard Home

AdGuard Home is a network-wide software for blocking ads & tracking. After you set it up, it'll cover ALL your home devices, and you don't need any client-side software for that.

## How does AdGuard Home work?

AdGuard Home operates as a DNS server that re-routes tracking domains to a "black hole," thus preventing your devices from connecting to those servers. It's based on software we use for our public [AdGuard DNS](https://adguard.com/en/adguard-dns/overview.html) servers -- both share a lot of common code.

## How is this different from public AdGuard DNS servers?

Running your own AdGuard Home server allows you to do much more than using a public DNS server.

* Choose what exactly will the server block or not block;
* Monitor your network activity;
* Add your own custom filtering rules;

In the future, AdGuard Home is supposed to become more than just a DNS server.

## Installation

### Mac

Download this file: [AdGuardHome_v0.9-hotfix1_MacOS.zip](https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.9-hotfix1/AdGuardHome_v0.9-hotfix1_MacOS.zip), then unpack it and follow ["How to run"](#how-to-run) instructions below.

### Linux 64-bit Intel

Download this file: [AdGuardHome_v0.9-hotfix1_linux_amd64.tar.gz](https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.9-hotfix1/AdGuardHome_v0.9-hotfix1_linux_amd64.tar.gz), then unpack it and follow ["How to run"](#how-to-run) instructions below.

### Linux 32-bit Intel

Download this file: [AdGuardHome_v0.9-hotfix1_linux_386.tar.gz](https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.9-hotfix1/AdGuardHome_v0.9-hotfix1_linux_386.tar.gz), then unpack it and follow ["How to run"](#how-to-run) instructions below.

### Raspberry Pi (32-bit ARM)

Download this file: [AdGuardHome_v0.9-hotfix1_linux_arm.tar.gz](https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.9-hotfix1/AdGuardHome_v0.9-hotfix1_linux_arm.tar.gz), then unpack it and follow ["How to run"](#how-to-run) instructions below.

## How to run

DNS works on port 53, which requires superuser privileges. Therefore, you need to run it with `sudo` in terminal:

```bash
sudo ./AdGuardHome
```

Now open the browser and navigate to http://localhost:3000/ to control your AdGuard Home service.

### Running without superuser

You can run AdGuard Home without superuser privileges, but you need to instruct it to use a different port rather than 53. You can do that by editing `AdGuardHome.yaml` and finding these two lines:

```yaml
coredns:
  port: 53
```

You can change port 53 to anything above 1024 to avoid requiring superuser privileges.

If the file does not exist, create it in the same folder, type these two lines down and save.

### Additional configuration

Upon the first execution, a file named `AdGuardHome.yaml` will be created, with default values written in it. You can modify the file while your AdGuard Home service is not running. Otherwise, any changes to the file will be lost because the running program will overwrite them.

Settings are stored in [YAML format](https://en.wikipedia.org/wiki/YAML), possible parameters that you can configure are listed below:

 * `bind_host` — Web interface IP address to listen on
 * `bind_port` — Web interface IP port to listen on
 * `auth_name` — Web interface optional authorization username
 * `auth_pass` — Web interface optional authorization password
 * `coredns` — CoreDNS configuration section
   * `port` — DNS server port to listen on
   * `filtering_enabled` — Filtering of DNS requests based on filter lists
   * `safebrowsing_enabled` — Filtering of DNS requests based on safebrowsing
   * `safesearch_enabled` — Enforcing "Safe search" option for search engines, when possible
   * `parental_enabled` — Parental control-based DNS requests filtering
   * `parental_sensitivity` — Age group for parental control-based filtering, must be either 3, 10, 13 or 17
   * `querylog_enabled` — Query logging (also used to calculate top 50 clients, blocked domains and requested domains for statistic purposes)
   * `bootstrap_dns` — DNS server used for initial hostnames resolution in case if upstream is DoH or DoT with a hostname
   * `upstream_dns` — List of upstream DNS servers
 * `filters` — List of filters, each filter has the following values:
   * `ID` - filter ID (must be unique)
   * `url` — URL pointing to the filter contents (filtering rules)
   * `enabled` — Current filter's status (enabled/disabled)
 * `user_rules` — User-specified filtering rules

Removing an entry from settings file will reset it to the default value. Deleting the file will reset all settings to the default values.

## How to build from source

### Prerequisites

You will need:

 * [go](https://golang.org/dl/) v1.11 or later.
 * [node.js](https://nodejs.org/en/download/)

You can either install it via the provided links or use [brew.sh](https://brew.sh/) if you're on Mac:

```bash
brew install go node
```

### Building

Open Terminal and execute these commands:

```bash
git clone https://github.com/AdguardTeam/AdGuardHome
cd AdGuardHome
make
```

## Contributing

You are welcome to fork this repository, make your changes and submit a pull request — https://github.com/AdguardTeam/AdGuardHome/pulls

## Reporting issues

If you run into any problem or have a suggestion, head to [this page](https://github.com/AdguardTeam/AdGuardHome/issues) and click on the `New issue` button.

## Acknowledgments

This software wouldn't have been possible without:

 * [Go](https://golang.org/dl/) and it's libraries:
   * [CoreDNS](https://coredns.io)
   * [packr](https://github.com/gobuffalo/packr)
   * [gcache](https://github.com/bluele/gcache)
   * [miekg's dns](https://github.com/miekg/dns)
   * [go-yaml](https://github.com/go-yaml/yaml)
 * [Node.js](https://nodejs.org/) and it's libraries:
   * [React.js](https://reactjs.org)
   * [Tabler](https://github.com/tabler/tabler)
   * And many more node.js packages.
 * [whotracks.me data](https://github.com/cliqz-oss/whotracks.me)

For a full list of all node.js packages in use, please take a look at [client/package.json](https://github.com/AdguardTeam/AdGuardHome/blob/master/client/package.json) file.
